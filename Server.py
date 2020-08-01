from flask import Flask, request, jsonify, redirect, send_file, Response
from utils import GetArgs
from flask_mongoengine import MongoEngine
from database import Document
import core
from werkzeug.utils import secure_filename
import os
import qrcode
import base64
import io
from flask_cors import CORS
import json
import time
import secrets
import authlib

# Initialize app
app = Flask(__name__)
CORS(app)

# Define a connection to the database
db = MongoEngine()
app.config['MONGODB_SETTINGS'] = {
    "db": "documentx",
    "host": "localhost",
    "port": 27017
}
db.init_app(app)

ALLOWED_EXTENSIONS = ['txt', 'pdf', 'doc',
                      'docx', 'xls', 'xlsx', 'ppt', 'pptx']
FILESTORAGE = '/etc/docx/fs'
# FILESTORAGE = "C:\\Temp\\"


def RequestErrorHandler(func, code, missing):
    return jsonify({
        'code': code,
        'message': 'Request failed. A valid value for '+missing+' is needed for this request.'
    })


def GeneralErrorHandler(code, message):
    return {
        'code': code,
        'message': message
    }


def allowedFile(filename):
    # Stolen from Flask Docs
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploadDocument', methods=['POST'])
@authlib.authDec()
@GetArgs(RequestErrorHandler)
def uploadDocument(name, subject, comments='', desc='', status='Recorded', docID=None):
    if 'file' not in request.files:
        return GeneralErrorHandler(-200, 'No file is uploaded.')
    f = request.files['file']
    if f.filename == '':
        return GeneralErrorHandler(-200, 'No file is uploaded.')
    if f and not allowedFile(f.filename):
        return GeneralErrorHandler(-201, 'Unsupported format')
    filename = secure_filename(f.filename)
    rst, docID = core.NewDocument(name=name, subject=subject, comments=comments,
                                  fileName=filename, desc=desc, status='Uploaded', docID=docID)
    f.save(os.path.join(FILESTORAGE, docID))
    return jsonify({
        'code': rst,
        'docID': docID
    })


@app.route('/getDocuments')
def getDocuments():
    r = []
    for x in core.GetDocuments():
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/getDocumentByID')
@GetArgs(RequestErrorHandler)
def getDocumentByDocumentID(docID):
    r = core.GetDocByDocID(docID)
    if r:
        r = r.to_mongo()
        r.pop('_id')
    else:
        r = {}
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsByID')
@GetArgs(RequestErrorHandler)
def searchDocumentsByID(docID):
    r = []
    for x in core.SearchDocsByDocID(docID):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsBySubject')
@GetArgs(RequestErrorHandler)
def searchDocumentsBySubject(subject):
    r = []
    for x in core.SearchDocsBySubject(subject):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsByName')
@GetArgs(RequestErrorHandler)
def searchDocumentsByName(name):
    r = []
    for x in core.SearchDocsByName(name):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/deleteDocumentByID')
@authlib.authDec()
@GetArgs(RequestErrorHandler)
def deleteDocumentByID(docID):
    if os.path.exists(os.path.join(FILESTORAGE, docID)) and os.path.isfile(os.path.join(FILESTORAGE, docID)):
        os.remove(os.path.join(FILESTORAGE, docID))
    return jsonify({
        'code': 0,
        'result': core.DeleteDocs(docID)
    })


@app.route('/viewDocumentByID')
@authlib.authDec('document_access')
@GetArgs(RequestErrorHandler)
def viewDocumentByID(docID):
    r = core.GetDocByDocID(docID)
    if r:
        redAddr = r.fileName
        auth = core.GetAuthCode(docID)
        if auth:
            return redirect('/secureAccess/'+redAddr+'?auth='+auth+'&docID='+docID)
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@app.route('/getDocumentAccessToken')
@authlib.authDec('document_access')
@GetArgs(RequestErrorHandler)
def getDocumentAccessToken(docID):
    r = core.GetDocByDocID(docID)
    if r:
        auth = core.GetAuthCode(docID)
        if auth:
            return jsonify({
                'code': 0,
                'auth': auth
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@app.route('/getDownloadLink')
@authlib.authDec('document_access')
@GetArgs(RequestErrorHandler)
def getDownloadLink(docID):
    r = core.GetDocByDocID(docID)
    if r:
        redAddr = r.fileName
        auth = core.GetAuthCode(docID)
        if auth:
            return jsonify({
                'code': 0,
                'link': '/secureAccess/'+redAddr+'?auth='+auth+'&docID='+docID
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@app.route('/editDocumentByID', methods=['GET', 'POST'])
@authlib.authDec()
@GetArgs(RequestErrorHandler)
def editDocumentByID(docID, properties, elToken=None):
    doc = core.GetDocByDocID(docID)
    if not doc:
        return GeneralErrorHandler(-301, 'Document does not exist')
    try:
        properties = json.loads(properties)
    except:
        return GeneralErrorHandler(-1, 'properties JSON parse error')

    if not isinstance(properties, dict):
        return GeneralErrorHandler(-1, 'properties should be a dictionary.')
    if 'fileName' in properties:
        return GeneralErrorHandler(-1, "field fileName is protected and can not be changed over the API.")

    success = []
    failed = []

    for prop in properties:
        if prop in doc:
            setattr(doc, prop, properties[prop])
            success.append(prop)
        else:
            failed.append(prop)

    if 'docID' in properties:
        try:
            os.rename(os.path.join(FILESTORAGE, docID),
                      os.path.join(FILESTORAGE, properties['docID']))
        except:
            return GeneralErrorHandler(-1, 'Failed to move the file')

    try:
        doc.save()
    except:
        if 'docID' in properties:
            try:
                # Rollback
                os.rename(os.path.join(FILESTORAGE, properties['docID']), os.path.join(
                    FILESTORAGE, docID))
            except:
                pass

        return GeneralErrorHandler(-302, 'Failed to save to the database.')

    return jsonify({
        'code': 0,
        'success': success,
        'failed': failed
    })


@app.route('/secureAccess/<path:path>')
@GetArgs(RequestErrorHandler)
def GetFile(auth=None, path=None, docID=None):
    if core.ValidatePermission(docID, auth):
        return send_file(os.path.join(FILESTORAGE, docID))
    return GeneralErrorHandler(-400, 'Access is denied'), 403


@app.route('/qr')
@GetArgs(RequestErrorHandler)
def GenerateQR(urlEncoded):
    imgByteArr = io.BytesIO()
    try:
        qrcode.make(base64.b64decode(urlEncoded.encode()).decode(),
                    border=0).save(imgByteArr, format='PNG')
    except:
        return Response(b'', mimetype='image/png')
    imgByteArr = imgByteArr.getvalue()
    return Response(imgByteArr, mimetype='image/png')

@app.route('/login', methods = ['POST'])
@authlib.authDec('login')
def login(uID):
    return jsonify({
        'code':0,
        'uID':uID,
        'name':core.GetUsernameByUID(uID)
        'token':core.GetToken(uID),
        'message':'Successfully logged in.'
    })
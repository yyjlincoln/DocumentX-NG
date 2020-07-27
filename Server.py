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

ALLOWED_EXTENSIONS = ['txt', 'pdf', 'doc', 'docx']
# FILESTORAGE = '/etc/docx/fs'
FILESTORAGE = "C:\\Temp\\"


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
@GetArgs(RequestErrorHandler)
def deleteDocumentByID(docID):
    if os.path.exists(os.path.join(FILESTORAGE, docID)) and os.path.isfile(os.path.join(FILESTORAGE, docID)):
        os.remove(os.path.join(FILESTORAGE, docID))
    return jsonify({
        'code': 0,
        'result': core.DeleteDocs(docID)
    })


@app.route('/viewDocumentByID')
@GetArgs(RequestErrorHandler)
def viewDocumentByID(docID, token=''):
    r = core.GetDocByDocID(docID)
    if r:
        redAddr = r.fileName
        auth = core.GetAuthCode(docID, token)
        if auth:
            return redirect('/secureAccess/'+redAddr+'?auth='+auth+'&docID='+docID)
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@app.route('/secureAccess/<path:path>')
@GetArgs(RequestErrorHandler)
def GetFile(auth=None, path=None, docID=None):
    if core.ValidatePermission(docID,auth):
        return send_file(os.path.join(FILESTORAGE, docID))
    return GeneralErrorHandler(-400,'Access is denied'), 403

@app.route('/qr')
@GetArgs(RequestErrorHandler)
def GenerateQR(urlEncoded):
    imgByteArr = io.BytesIO()
    qrcode.make(base64.b64decode(urlEncoded.encode()).decode(),border=0).save(imgByteArr, format='PNG')
    imgByteArr = imgByteArr.getvalue()
    return Response(imgByteArr,mimetype='image/png')

app.run()


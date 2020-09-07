from flask import Flask, request, jsonify, redirect, send_file, Response
from utils import GetArgs
from flask_mongoengine import MongoEngine
from database import Document, User, Policy
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
import filestore

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


@app.route('/setTokenMaxAge')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def setTokenMaxAge(uID, maxage):
    try:
        maxage = float(maxage)
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid maxage.'
        })
    if maxage >= 15 or maxage == 0:
        if core.SetTokenMaxAge(uID, maxage):
            return jsonify({
                'code': 0,
                'message': 'success'
            })
        return jsonify({
            'code': -1,
            'message': 'Failed to set max age'
        })
    return jsonify({
        'code': -1,
        'message': 'Max age must be greater than 15s.'
    })


@app.route('/uploadDocument', methods=['POST'])
# Change to verify_permission and allow authdec to pass args to the auth handler
@authlib.authDec('verify_upload')
@GetArgs(RequestErrorHandler)
def uploadDocument(name, subject, uID, comments='', desc='', status='Recorded', docID=None):
    if 'file' not in request.files:
        return GeneralErrorHandler(-200, 'No file is uploaded.')
    f = request.files['file']
    if f.filename == '':
        return GeneralErrorHandler(-200, 'No file is uploaded.')
    if f and not allowedFile(f.filename):
        return GeneralErrorHandler(-201, 'Unsupported format')
    filename = secure_filename(f.filename)
    rst, docID = core.NewDocument(name=name, subject=subject, comments=comments,
                                  fileName=filename, desc=desc, status='Uploaded', docID=docID, owner=uID)
    f.save(filestore.newStorageLocation(docID))
    return jsonify({
        'code': rst,
        'docID': docID
    })


@app.route('/share')
@authlib.authDec('doc_write')
@GetArgs(RequestErrorHandler)
def shareDocument(uID, targetUID, docID, read='true', write='false'):
    d = core.GetDocByDocID(docID)
    read = True if read == 'true' else False
    write = True if write == 'true' else False
    if d:
        try:
            # Try if the policy for that user exists
            for x in range(len(d.policies)-1, -1, -1):
                if str(d.policies[x].uID).lower() == targetUID.lower():
                    d.policies.pop(x)
            
            if read or write:
                d.policies.append(Policy(uID=targetUID, read=read, write=write))

            d.save()
            return jsonify({
                'code': 0,
                'result': {
                    'targetUID': targetUID,
                    'read': read,
                    'write': write
                }
            })
        except Exception as e:
            print(e)
            return jsonify({
                'code': -1,
                'message': 'Error'
            })

    return jsonify({
        'code': -1,
        'message': 'Error'
    })


@app.route('/getDocuments')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def getDocuments(uID=None, status='active', start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start<=end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })
    archived = False
    if status == 'active':
        archived = False
    elif status == 'archived':
        archived = True
    else:
        archived = None

    r = []
    for x in core.GetDocuments(uID=uID, archived=archived, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/getDocumentByID')
@authlib.authDec('doc_read')
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
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def searchDocumentsByID(uID, docID, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start<=end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByDocID(uID, docID, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })

@app.route('/getHashTags')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def getHashTags(uID):
    r = core.GetUserHashTags(uID)
    return jsonify({
        'code':0,
        'result':r
    })

@app.route('/searchDocumentsByHashTag')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def searchDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start<=end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByHashTag(uID, hashTag, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsBySubject')
@authlib.authDec('verify_token')  # TODO change
@GetArgs(RequestErrorHandler)
def searchDocumentsBySubject(uID, subject, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start<=end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsBySubject(uID, subject, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsByName')
@authlib.authDec('verify_token')  # TODO change
@GetArgs(RequestErrorHandler)
def searchDocumentsByName(uID, name, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start<=end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByName(uID, name, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return jsonify({
        'code': 0,
        'result': r
    })


@app.route('/deleteDocumentByID')
@authlib.authDec('doc_write')
@GetArgs(RequestErrorHandler)
def deleteDocumentByID(docID):
    if os.path.exists(os.path.join(FILESTORAGE, docID)) and os.path.isfile(os.path.join(FILESTORAGE, docID)):
        os.remove(os.path.join(FILESTORAGE, docID))
    return jsonify({
        'code': 0,
        'result': core.DeleteDocs(docID)
    })

# The authentication has been removed since this function has been depriciated.


@app.route('/viewDocumentByID')
@GetArgs(RequestErrorHandler)
def viewDocumentByID(docID):
    return redirect('https://mcsrv.icu/view?docID='+str(docID))


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
@authlib.authDec('doc_write')
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
        return send_file(filestore.getStorageLocation(docID))
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


@app.route('/login', methods=['POST'])
@authlib.authDec('login')
@GetArgs(RequestErrorHandler)
def login(uID):
    # Get name
    u = core.GetUserByID(uID)
    if not u:
        return {
            'code': -404,
            'message': 'User does not exist'
        }
    r = core.GetUserToken(uID)
    return jsonify({
        'code': r['code'],
        'uID': u.uID,
        'message': r['message'],
        'token': r['token'],
        'name': u.name
    })


@app.route('/register', methods=['POST'])
@GetArgs(RequestErrorHandler)
def register(uID, name, password):
    return jsonify(core.NewUser(uID, name, password))


@app.route('/getAuthStatus')
@authlib.authDec('verify_token')
def getAuthStatus():
    return {
        'code': 0,
        'message': 'Auth ok'
    }

# app.run('localhost',port=80)

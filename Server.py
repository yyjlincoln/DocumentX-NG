from flask import Flask, request, jsonify, redirect, send_file, Response
from utils import GetArgs
from flask_mongoengine import MongoEngine
from database import Document, User, Policy
import core
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

_windows_device_files = (
    "CON",
    "AUX",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "LPT1",
    "LPT2",
    "LPT3",
    "PRN",
    "NUL",
)

SAFE_CHARACTERS = ['.','_','%','!',' ','《','》','、','&','^','$','#', '-','，']

def secure_filename(name):
    name = name.replace('/','_')
    n =  "".join([c for c in name if c.isalpha() or c.isdigit() or c in SAFE_CHARACTERS]).rstrip()
    if n not in _windows_device_files and n!='' and n!='.':
        return n
    else:
        return 'InvalidFileName.File'

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
           filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS


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
                d.policies.append(
                    Policy(uID=targetUID, read=read, write=write))

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
        assert start <= end
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
        assert start <= end
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
        'code': 0,
        'result': r
    })


@app.route('/searchDocumentsByHashTag')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def searchDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
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


@app.route('/getDocumentsByHashTag')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def getDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsByHashTag(uID, hashTag, start=start, end=end):
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
        assert start <= end
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


@app.route('/getDocumentsBySubject')
@authlib.authDec('verify_token')  # TODO change
@GetArgs(RequestErrorHandler)
def getDocumentsBySubject(uID, subject, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsBySubject(uID, subject, start=start, end=end):
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
        assert start <= end
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


@app.route('/getDocumentsByName')
@authlib.authDec('verify_token')  # TODO change
@GetArgs(RequestErrorHandler)
def getDocumentsByName(uID, name, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsByName(uID, name, start=start, end=end):
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
    if os.path.exists(filestore.getStorageLocation(docID)) and os.path.isfile(filestore.getStorageLocation(docID)):
        os.remove(filestore.getStorageLocation(docID))
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
        # redAddr = r.fileName
        redAddr = secure_filename(r.name + '.' + r.fileName.rsplit('.', 1)[-1].lower())
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
def editDocumentByID(docID, properties, elToken=None, uID=None):
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
            if filestore.getStorageLocation(docID):
                os.rename(filestore.getStorageLocation(docID),
                          filestore.newStorageLocation(properties['docID']))
            else:
                raise Exception('Could not save the file')
        except:
            return GeneralErrorHandler(-1, 'Failed to move the file')

        # Also, change the DocumentProperties
        d = core.GetAllDocumentProperties(docID=docID)
        for x in d:
            try:
                x.docID = properties['docID']
            except:
                print('Warn: Could not change docID in DocumentProperties.')

    try:
        doc.save()
        try:
            for x in d:
                x.save()
        except:
            print('Warn: Could not save changed DocumentProperties.')
    except:
        if 'docID' in properties:
            try:
                # Rollback
                os.rename(filestore.getStorageLocation(
                    properties['docID']), filestore.newStorageLocation(docID))
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


@app.route('/getResourceGroupByID')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def GetResourceGroupByID(uID, resID):
    r = core.GetResourceGroupByID(uID, resID)
    if r:
        return jsonify({
            'code': 0,
            'message': 'Successfully obtained resource group info.',
            'resourceGroup': {
                'resID': r.resID,
                'name': r.name,
                'uID': r.uID
            }
        })
    return {
        'code': -303,
        'message': f'ResourceGroup "{str(resID)}" does not exist.'
    }


@app.route('/newResourceGroup')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def NewResourceGroup(uID, resID, name):
    if core.NewResourceGroup(uID=uID, resID=resID, name=name):
        return jsonify({
            'code': 0,
            'message': f'Successfully added resource group "{name}"({resID}) for user {uID}".'
        })
    return jsonify({
        'code': -1,
        'message': 'Could not add this new resource group.'
    })


@app.route('/deleteResourceGroupByID')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def DeleteResourceGroupByID(uID, resID):
    if not core.GetResourceGroupByID(uID, resID):
        # Resource Group does not exist!
        return jsonify({
            'code': 0,
            'message': 'Resource Group does not exist! You don\'t have to delete it.'
        })
    if core.DeleteResourceGroupByID(uID, resID):
        return jsonify({
            'code': 0,
            'message': 'Successfully deleted resource group.'
        })
    return jsonify({
        'code': -1,
        'message': 'Failed to delete this resource group.'
    })


@app.route('/editResourceGroupByID')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def EditResourceGroupByID(uID, resID, properties):
    try:
        properties = json.loads(properties)
    except json.JSONDecodeError:
        return jsonify({
            'code': -1,
            'message': 'JSON Decode Failed.'
        })

    if not isinstance(properties, dict):
        return jsonify({
            'code': -1,
            'message': 'Properties should be a dict.'
        })
    if core.EditResourceGroupByID(uID, resID, properties):
        return jsonify({
            'code': 0,
            'message': 'Successfully updated resource group.'
        })
    return jsonify({
        'code': -1,
        'message': 'Failed to update the resource group.'
    })


@app.route('/getResourceGroups')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def getResourceGroups(uID):
    r = core.GetResourceGroups(uID)
    rp = []
    for resg in r:
        rp.append({
            'documents': resg['documents'],
            'name': resg['name'],
            'resID': resg['resID'],
            'uID': resg['uID'],
            'priority': resg['priority']
        })
    return jsonify({
        'code': 0,
        'resourceGroups': rp
    })


@app.route('/getDocumentsByResourceGroup')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def getDocumentsByResourceGroup(uID, resID):
    return jsonify({
        'code': 0,
        'documents': core.GetDocumentsByResourceGroup(uID, resID)
    })


@app.route('/addDocumentToResourceGroup')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def addDocumentsToResourceGroup(uID, resID, docID):
    # Check if resGroup exists
    if not core.GetResourceGroupByID(uID, resID):
        return jsonify({
            'code': -303,
            'message': 'Resource group does not exist'
        })
    if not core.GetDocByDocID(docID):
        return jsonify({
            'code': -301,
            'message': 'Document does not exist!'
        })

    r = core.AddDocumentToResourceGroup(uID, resID, docID)
    if r:
        return jsonify({
            'code': 0,
            'message': 'Success'
        })
    return jsonify({
        'code': -1,
        'message': 'Failed to add document.'
    })


@app.route('/removeDocumentFromResourceGroup')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def removeDocumentsToResourceGroup(uID, resID, docID):
    if not core.GetResourceGroupByID(uID, resID):
        return jsonify({
            'code': -303,
            'message': 'Resource group does not exist'
        })
    r = core.RemoveDocumentFromResourceGroup(uID, resID, docID)
    if r:
        return jsonify({
            'code': 0,
            'message': 'Success'
        })
    return jsonify({
        'code': -1,
        'message': 'Failed to remove document.'
    })


@app.route('/newToken')
@authlib.authDec('elevated')
@GetArgs(RequestErrorHandler)
def newToken(uID, maxAge=30*3600*24):
    try:
        maxAge = int(maxAge)
    except:
        return jsonify({
            'code': -1,
            'message': 'Invalid max age.'
        })

    return core.GetUserToken(uID, tokenMaxAge=maxAge)


@app.route('/remoteLogin')
@GetArgs(RequestErrorHandler)
def remoteLoginRequest():
    r = core.NewRemoteLogin()
    if r:
        return jsonify({
            'code': 0,
            'rID': r
        })
    return jsonify({
        'code': -1,
        'message': 'Could not initiate'
    })


@app.route('/approveRemoteLogin')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def approveRemoteLogin(rID, uID, token, tempToken=''):
    if tempToken:
        r = core.ApproveRemoteLogin(rID, uID,  token='')
    else:
        r = core.ApproveRemoteLogin(rID, uID, token)

    if r:
        return jsonify({
            'code': 0,
            'message': 'Request approved.'
        })
    return jsonify({
        'code': -1,
        'message': 'Can not approve request. Does the request exist?'
    })


@app.route('/rejectRemoteLogin')
@authlib.authDec('verify_token')
@GetArgs(RequestErrorHandler)
def rejectRemoteLogin(rID):
    core.RejectRemoteLogin(rID)
    return jsonify({
        'code': 0,
        'message': 'Request rejected.'
    })


@app.route('/refreshRemoteLogin')
@GetArgs(RequestErrorHandler)
def refreshRemoteLogin(rID):
    core.clearRemoteLogin()
    r = core.GetRemoteLogin(rID)
    if r:
        if r.auth == 0:
            uID = r.uID
            if r.token:
                # Instead of giving the existing token, generate a new one
                # as this makes it easier to auth with a ltat device.
                # token = r.token
                token = core.GetUserToken(uID)['token']
            else:
                # Temp token
                token = core.GetUserToken(uID, tokenMaxAge=15)['token']

            r.delete()
            return jsonify({
                'code': 0,
                'uID': uID,
                'token': token,
                'name': core.GetUserByID(uID).name
            })
        return jsonify({
            'code': r.auth,
            'message': 'Not authenticated yet'
        })
    return jsonify({
        'code': -1,
        'message': 'Login request not found or expired.'
    })

@app.route('/validateRemoteLogin')
@GetArgs(RequestErrorHandler)
def validateRemoteLogin(rID):
    r =  core.GetRemoteLogin(rID)
    if r:
        r.auth = 2
        r.save()
        return jsonify({
            'code':0,
            'message':'Request exist.'
        })
    return jsonify({
        'code':-1,
        'message':'Request does not exist!'
    })
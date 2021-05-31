from flask import Flask, request, jsonify, redirect, send_file, Response
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
from utils.AutoArguments import Arg
from utils.RequestMapping import RequestMap
from utils.ResponseModule import Res

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
                      'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'png', 'jpg', 'jpeg', 'heic', 'mp4', 'mp3']

EXTENSION_MIME = {
    'pdf':'application/pdf',
    'png':'image/png',
    'docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'zip':'application/zip',
    'mp4':'video/mp4',
    'mp3':'audio/mpeg'
}

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

SAFE_CHARACTERS = ['.', '_', '%', '!', ' ',
                   '《', '》', '、', '&', '^', '$', '#', '-', '，']


def secure_filename(name):
    name = name.replace('/', '_')
    n = "".join([c for c in name if c.isalpha() or c.isdigit()
                 or c in SAFE_CHARACTERS]).rstrip()
    if n not in _windows_device_files and n != '' and n != '.':
        return n
    else:
        return 'InvalidFileName.File'


def RequestErrorHandler(func, code, missing):
    return Res(**{
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


rmap = RequestMap(always_pass_channel_and_fetch_values=True)


@rmap.register_request('/setTokenMaxAge')
@authlib.authDec('verify_token')
@Arg()
def setTokenMaxAge(uID, maxage):
    try:
        maxage = float(maxage)
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid maxage.'
        })
    if maxage >= 15 or maxage == 0:
        if core.SetTokenMaxAge(uID, maxage):
            return Res(**{
                'code': 0,
                'message': 'success'
            })
        return Res(**{
            'code': -1,
            'message': 'Failed to set max age'
        })
    return Res(**{
        'code': -1,
        'message': 'Max age must be greater than 15s.'
    })


@rmap.register_request('/uploadDocument', methods=['POST'])
# Change to verify_permission and allow authdec to pass args to the auth handler
@authlib.authDec('verify_upload')
@Arg()
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
    return Res(**{
        'code': rst,
        'docID': docID
    })


@rmap.register_request('/share')
@authlib.authDec('doc_write')
@Arg()
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
            return Res(**{
                'code': 0,
                'result': {
                    'targetUID': targetUID,
                    'read': read,
                    'write': write
                }
            })
        except Exception as e:
            print(e)
            return Res(**{
                'code': -1,
                'message': 'Error'
            })

    return Res(**{
        'code': -1,
        'message': 'Error'
    })


@rmap.register_request('/getDocuments')
@authlib.authDec('verify_token')
@Arg()
def getDocuments(uID=None, status='active', start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
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
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/getDocumentByID')
@authlib.authDec('doc_read')
@Arg()
def getDocumentByDocumentID(docID):
    r = core.GetDocByDocID(docID)
    if r:
        r = r.to_mongo()
        r.pop('_id')
    else:
        r = {}
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/searchDocumentsByID')
@authlib.authDec('verify_token')
@Arg()
def searchDocumentsByID(uID, docID, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByDocID(uID, docID, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/getHashTags')
@authlib.authDec('verify_token')
@Arg()
def getHashTags(uID):
    r = core.GetUserHashTags(uID)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/searchDocumentsByHashTag')
@authlib.authDec('verify_token')
@Arg()
def searchDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByHashTag(uID, hashTag, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/getDocumentsByHashTag')
@authlib.authDec('verify_token')
@Arg()
def getDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsByHashTag(uID, hashTag, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/searchDocumentsBySubject')
@authlib.authDec('verify_token')  # TODO change
@Arg()
def searchDocumentsBySubject(uID, subject, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsBySubject(uID, subject, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/getDocumentsBySubject')
@authlib.authDec('verify_token')  # TODO change
@Arg()
def getDocumentsBySubject(uID, subject, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsBySubject(uID, subject, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/searchDocumentsByName')
@authlib.authDec('verify_token')  # TODO change
@Arg()
def searchDocumentsByName(uID, name, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.SearchDocsByName(uID, name, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/getDocumentsByName')
@authlib.authDec('verify_token')  # TODO change
@Arg()
def getDocumentsByName(uID, name, start='0', end='50'):
    try:
        start = int(start)
        end = int(end)
        assert start <= end
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid start / end'
        })

    r = []
    for x in core.GetDocsByName(uID, name, start=start, end=end):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        r.append(Q)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/deleteDocumentByID')
@authlib.authDec('doc_write')
@Arg()
def deleteDocumentByID(docID):
    if os.path.exists(filestore.getStorageLocation(docID)) and os.path.isfile(filestore.getStorageLocation(docID)):
        os.remove(filestore.getStorageLocation(docID))
    return Res(**{
        'code': 0,
        'result': core.DeleteDocs(docID)
    })

# The authentication has been removed since this function has been depriciated.


@rmap.register_request('/viewDocumentByID')
@Arg()
def viewDocumentByID(docID):
    return redirect('https://mcsrv.icu/view?docID='+str(docID))


@rmap.register_request('/getDocumentAccessToken')
@authlib.authDec('document_access')
@Arg()
def getDocumentAccessToken(docID):
    r = core.GetDocByDocID(docID)
    if r:
        auth = core.GetAuthCode(docID)
        if auth:
            return Res(**{
                'code': 0,
                'auth': auth
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@rmap.register_request('/getDownloadLink')
@authlib.authDec('document_access')
@Arg()
def getDownloadLink(docID):
    r = core.GetDocByDocID(docID)
    if r:
        # redAddr = r.fileName
        redAddr = secure_filename(
            r.name + '.' + r.fileName.rsplit('.', 1)[-1].lower())
        auth = core.GetAuthCode(docID)
        if auth:
            return Res(**{
                'code': 0,
                'link': '/download/'+redAddr+'?auth='+auth+'&docID='+docID
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')

@rmap.register_request('/getPreviewLink')
@authlib.authDec('document_access')
@Arg()
def getPreviewLink(docID):
    r = core.GetDocByDocID(docID)
    if r:
        # redAddr = r.fileName
        redAddr = secure_filename(
            r.name + '.' + r.fileName.rsplit('.', 1)[-1].lower())
        auth = core.GetAuthCode(docID)
        if auth:
            return Res(**{
                'code': 0,
                'link': '/preview/'+redAddr+'?auth='+auth+'&docID='+docID
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@rmap.register_request('/editDocumentByID', methods=['GET', 'POST'])
@authlib.authDec('doc_write')
@Arg()
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

    return Res(**{
        'code': 0,
        'success': success,
        'failed': failed
    })


@app.route('/download/<path:path>')
@Arg()
def GetFile(docID, auth=None, path=None):
    if core.ValidatePermission(docID, auth):
        return send_file(filestore.getStorageLocation(docID))
    return GeneralErrorHandler(-400, 'Access is denied'), 403

@app.route('/preview/<path:path>')
@Arg()
def GetFilePreview(docID, auth=None, path=None):
    if core.ValidatePermission(docID, auth):
        doc = core.GetDocByDocID(docID)
        extension = doc.fileName.rsplit('.', 1)[-1].lower()
        MIME = None
        if extension in EXTENSION_MIME:
            MIME = EXTENSION_MIME[extension]
        return send_file(filestore.getStorageLocation(docID), mimetype=MIME)
    return GeneralErrorHandler(-400, 'Access is denied'), 403


@app.route('/qr')
@Arg()
def GenerateQR(urlEncoded):
    imgByteArr = io.BytesIO()
    try:
        qrcode.make(base64.b64decode(urlEncoded.encode()).decode(),
                    border=0).save(imgByteArr, format='PNG')
    except:
        return Response(b'', mimetype='image/png')
    imgByteArr = imgByteArr.getvalue()
    return Response(imgByteArr, mimetype='image/png')


@rmap.register_request('/login', methods=['POST'])
@authlib.authDec('login')
@Arg()
def login(uID):
    # Get name
    u = core.GetUserByID(uID)
    if not u:
        return {
            'code': -404,
            'message': 'User does not exist'
        }
    r = core.GetUserToken(uID)
    return Res(**{
        'code': r['code'],
        'uID': u.uID,
        'message': r['message'],
        'token': r['token'],
        'name': u.name
    })


@rmap.register_request('/register', methods=['POST'])
@Arg()
def register(uID, name, password):
    return Res(**core.NewUser(uID, name, password))


@rmap.register_request('/getAuthStatus')
@authlib.authDec('verify_token')
@Arg()
def getAuthStatus():
    return {
        'code': 0,
        'message': 'Auth ok'
    }

# app.run('localhost',port=80)


@rmap.register_request('/getResourceGroupByID')
@authlib.authDec('verify_token')
@Arg()
def GetResourceGroupByID(uID, resID):
    r = core.GetResourceGroupByID(uID, resID)
    if r:
        return Res(**{
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


@rmap.register_request('/newResourceGroup')
@authlib.authDec('verify_token')
@Arg()
def NewResourceGroup(uID, resID, name):
    if core.NewResourceGroup(uID=uID, resID=resID, name=name):
        return Res(**{
            'code': 0,
            'message': f'Successfully added resource group "{name}"({resID}) for user {uID}".'
        })
    return Res(**{
        'code': -1,
        'message': 'Could not add this new resource group.'
    })


@rmap.register_request('/deleteResourceGroupByID')
@authlib.authDec('verify_token')
@Arg()
def DeleteResourceGroupByID(uID, resID):
    if not core.GetResourceGroupByID(uID, resID):
        # Resource Group does not exist!
        return Res(**{
            'code': 0,
            'message': 'Resource Group does not exist! You don\'t have to delete it.'
        })
    if core.DeleteResourceGroupByID(uID, resID):
        return Res(**{
            'code': 0,
            'message': 'Successfully deleted resource group.'
        })
    return Res(**{
        'code': -1,
        'message': 'Failed to delete this resource group.'
    })


@rmap.register_request('/editResourceGroupByID')
@authlib.authDec('verify_token')
@Arg()
def EditResourceGroupByID(uID, resID, properties):
    try:
        properties = json.loads(properties)
    except json.JSONDecodeError:
        return Res(**{
            'code': -1,
            'message': 'JSON Decode Failed.'
        })

    if not isinstance(properties, dict):
        return Res(**{
            'code': -1,
            'message': 'Properties should be a dict.'
        })
    if core.EditResourceGroupByID(uID, resID, properties):
        return Res(**{
            'code': 0,
            'message': 'Successfully updated resource group.'
        })
    return Res(**{
        'code': -1,
        'message': 'Failed to update the resource group.'
    })


@rmap.register_request('/getResourceGroups')
@authlib.authDec('verify_token')
@Arg()
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
    return Res(**{
        'code': 0,
        'resourceGroups': rp
    })


@rmap.register_request('/getDocumentsByResourceGroup')
@authlib.authDec('verify_token')
@Arg()
def getDocumentsByResourceGroup(uID, resID):
    return Res(**{
        'code': 0,
        'documents': core.GetDocumentsByResourceGroup(uID, resID)
    })


@rmap.register_request('/addDocumentToResourceGroup')
@authlib.authDec('verify_token')
@Arg()
def addDocumentsToResourceGroup(uID, resID, docID):
    # Check if resGroup exists
    if not core.GetResourceGroupByID(uID, resID):
        return Res(**{
            'code': -303,
            'message': 'Resource group does not exist'
        })
    if not core.GetDocByDocID(docID):
        return Res(**{
            'code': -301,
            'message': 'Document does not exist!'
        })

    r = core.AddDocumentToResourceGroup(uID, resID, docID)
    if r:
        return Res(**{
            'code': 0,
            'message': 'Success'
        })
    return Res(**{
        'code': -1,
        'message': 'Failed to add document.'
    })


@rmap.register_request('/removeDocumentFromResourceGroup')
@authlib.authDec('verify_token')
@Arg()
def removeDocumentsToResourceGroup(uID, resID, docID):
    if not core.GetResourceGroupByID(uID, resID):
        return Res(**{
            'code': -303,
            'message': 'Resource group does not exist'
        })
    r = core.RemoveDocumentFromResourceGroup(uID, resID, docID)
    if r:
        return Res(**{
            'code': 0,
            'message': 'Success'
        })
    return Res(**{
        'code': -1,
        'message': 'Failed to remove document.'
    })


@rmap.register_request('/newToken')
@authlib.authDec('elevated')
@Arg()
def newToken(uID, maxAge=30*3600*24):
    try:
        maxAge = int(maxAge)
    except:
        return Res(**{
            'code': -1,
            'message': 'Invalid max age.'
        })

    return core.GetUserToken(uID, tokenMaxAge=maxAge)


@rmap.register_request('/remoteLogin')
@Arg()
def remoteLoginRequest():
    r = core.NewRemoteLogin()
    if r:
        return Res(**{
            'code': 0,
            'rID': r
        })
    return Res(**{
        'code': -1,
        'message': 'Could not initiate'
    })


@rmap.register_request('/approveRemoteLogin')
@authlib.authDec('verify_token')
@Arg()
def approveRemoteLogin(rID, uID, token, tempToken=''):
    if tempToken:
        r = core.ApproveRemoteLogin(rID, uID,  token='')
    else:
        r = core.ApproveRemoteLogin(rID, uID, token)

    if r:
        return Res(**{
            'code': 0,
            'message': 'Request approved.'
        })
    return Res(**{
        'code': -1,
        'message': 'Can not approve request. Does the request exist?'
    })


@rmap.register_request('/rejectRemoteLogin')
@authlib.authDec('verify_token')
@Arg()
def rejectRemoteLogin(rID):
    core.RejectRemoteLogin(rID)
    return Res(**{
        'code': 0,
        'message': 'Request rejected.'
    })


@rmap.register_request('/refreshRemoteLogin')
@Arg()
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
            return Res(**{
                'code': 0,
                'uID': uID,
                'token': token,
                'name': core.GetUserByID(uID).name
            })
        return Res(**{
            'code': r.auth,
            'message': 'Not authenticated yet'
        })
    return Res(**{
        'code': -1,
        'message': 'Login request not found or expired.'
    })


@rmap.register_request('/validateRemoteLogin')
@Arg()
def validateRemoteLogin(rID):
    r = core.GetRemoteLogin(rID)
    if r:
        r.auth = 2
        r.save()
        return Res(**{
            'code': 0,
            'message': 'Request exist.'
        })
    return Res(**{
        'code': -1,
        'message': 'Request does not exist!'
    })


@app.route('/batch', methods=['GET', 'POST'])
@Arg(batch=json.loads)
def batch_request(batch):
    return rmap.parse_batch(batch)


rmap.handle_flask(app)



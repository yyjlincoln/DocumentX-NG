from typing import Dict
from flask import Flask, request, jsonify, redirect, send_file, Response
from flask_mongoengine import MongoEngine
from database import AccessLog, Document, User, Policy
import core
import os
import qrcode
import base64
import io
import json
import time
import secrets
import authlib
import filestore
from utils.AutoArguments import Arg
from utils.RequestMapping import RequestMap
from utils.ResponseModule import Res, ResponseAutoDeprecationWarning
from utils.AutoArgValidators import StringBool
import script
from core import Log

# Initialize app
app = Flask(__name__)

FRONTEND_ROOT = 'https://mcsrv.icu'

ALLOWED_EXTENSIONS = ['txt', 'pdf', 'doc',
                      'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'png', 'jpg', 'jpeg', 'heic', 'mp4', 'mp3', 'json', 'note']

EXTENSION_MIME = {
    'pdf': 'application/pdf',
    'png': 'image/png',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'zip': 'application/zip',
    'mp4': 'video/mp4',
    'mp3': 'audio/mpeg'
}


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
    filename = core.secure_filename(f.filename)
    rst, docID = core.NewDocument(name=name, subject=subject, comments=comments,
                                  fileName=filename, desc=desc, status='Uploaded', docID=docID, owner=uID)
    r = filestore.saveFile(docID, f.read())
    Log(uID, 'uploadDocument', docID)
    if not r:
        return Res(-1, 'failed to save file')
    return Res(**{
        'code': rst,
        'docID': docID
    })


@rmap.register_request('/share')
@authlib.authDec('doc_write')
@Arg(read=StringBool, write=StringBool)
def shareDocument(uID, targetUID, docID, read='true', write='false'):
    Log(uID, 'shareDocument', docID, info={
        'targetUID': targetUID,
        'read': read,
        'write': write
    })
    return Res(**core.shareDocument(targetUID, docID, read=read, write=write))


@rmap.register_request('/getDocuments')
@authlib.authDec('verify_token')
@Arg()
def getDocuments(uID=None, status='active', start='0', end='50'):
    Log(uID, 'getDocuments')
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
def getDocumentByDocumentID(docID, uID=None):
    r = core.GetDocByDocID(docID)
    if r:
        Log(uID, 'getDocumentByDocumentID', docID)
        r = r.to_mongo()
        r.pop('_id')
        r['shareable'] = core.GetIfShareable(uID, docID)
        r['sharename'] = core.GetDownloadName(docID)
        return Res(**{
            'code': 0,
            'result': r
        })
    else:
        r = {}
        return Res(**{
            'code': -301,
            'message': 'Document does not exist!',
            'result': {}
        })


@rmap.register_request('/searchDocumentsByID')
@authlib.authDec('verify_token')
@Arg()
def searchDocumentsByID(uID, docID, start='0', end='50'):
    Log(uID, 'searchDocumentsByID', docID)
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
    Log(uID, 'getHashTags')
    r = core.GetUserHashTags(uID)
    return Res(**{
        'code': 0,
        'result': r
    })


@rmap.register_request('/searchDocumentsByHashTag')
@authlib.authDec('verify_token')
@Arg()
def searchDocumentsByHashTag(uID, hashTag, start='0', end='50'):
    Log(uID, 'searchDocumentsByHashTag', info={
        'hashTag': hashTag
    })
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
    Log(uID, 'getDocumentsByHashTag', info={
        'hashTag': hashTag
    })
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
    Log(uID, 'searchDocumentsBySubject', info={
        'subject': subject
    })
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
    Log(uID, 'getDocumentsBySubject', info={
        'subject': subject
    })
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
    Log(uID, 'searchDocumentsByName', info={
        'name': name
    })
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
    Log(uID, 'getDocumentsByName', info={
        'name': name
    })
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
def deleteDocumentByID(docID, uID=None):
    Log(uID, 'deleteDocumentByID', docID)
    filestore.deleteFile(docID)
    return Res(**{
        'code': 0,
        'result': core.DeleteDocs(docID)
    })


@rmap.register_request('/reportDocumentByID')
@authlib.authDec('doc_read')
@Arg()
def reportDocumentByID(docID, uID=None):
    Log(uID, 'reportDocumentByID', docID)
    # Dummy function. TODO.
    return Res(code=0)

# The authentication has been removed since this function has been deprecated.


@rmap.register_request('/viewDocumentByID')
@Arg()
def viewDocumentByID(docID):
    return redirect(FRONTEND_ROOT+'/view?docID='+str(docID))


@rmap.register_request('/getDocumentAccessToken')
@authlib.authDec('document_access')
@Arg()
def getDocumentAccessToken(docID, uID=None):
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
@authlib.authDec('document_download')
@Arg()
def getDownloadLink(docID):
    r = core.GetDocByDocID(docID)
    if r:
        redAddr = core.GetDownloadName(docID)
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
        redAddr = core.GetDownloadName(docID)
        auth = core.GetAuthCode(docID)
        if auth:
            return Res(**{
                'code': 0,
                'link': '/preview/'+redAddr+'?auth='+auth+'&docID='+docID
            })
        return GeneralErrorHandler(-1, 'Could not get auth.')
    else:
        return GeneralErrorHandler(-301, 'Document does not exist')


@rmap.register_request('/editDocumentByID')
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
    if 'docID' in properties and properties['docID'] != docID:
        return GeneralErrorHandler(-1, 'you can not change the docID.')

    Log(uID, 'editDocumentByID', docID, properties)

    success = []
    failed = []

    for prop in properties:
        if prop in doc:
            setattr(doc, prop, properties[prop])
            success.append(prop)
        else:
            failed.append(prop)

    try:
        doc.save()
    except:
        return GeneralErrorHandler(-302, 'Failed to save to the database.')

    return Res(**{
        'code': 0,
        'success': success,
        'failed': failed
    })


@app.route('/download/<path:path>')
@Arg()
def GetFile(docID, auth=None, path=None):
    filename = core.GetDownloadName(docID, default='unknown')
    if core.ValidatePermission(docID, auth):
        return send_file(filestore.getStorageLocation(docID), download_name=filename, as_attachment=True, mimetype='application/octet-stream')

    # For download, we shall not redirect for re-authentication.
    return GeneralErrorHandler(-400, 'Access is denied'), 403


@app.route('/preview/<path:path>')
@Arg()
def GetFilePreview(docID, auth=None, path=None):
    if core.ValidatePermission(docID, auth):
        filename = core.GetDownloadName(docID, default='unknown')
        doc = core.GetDocByDocID(docID)
        extension = doc.fileName.rsplit('.', 1)[-1].lower()
        MIME = None
        if extension in EXTENSION_MIME:
            MIME = EXTENSION_MIME[extension]
        return send_file(filestore.getStorageLocation(docID), mimetype=MIME, download_name=filename)
    # Attempts to re-authorize
    return redirect(FRONTEND_ROOT+'/view?docID='+docID)
    # return GeneralErrorHandler(-400, 'Access is denied'), 403


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


@rmap.register_request('/initialise')
@Arg()
def entrypoint(uID=None):
    Log(uID, 'appInitialise')
    return Res(0, 'OK')


@rmap.register_request('/login')
@authlib.authDec('login')
@Arg()
def login(uID, apiversion='0', accessedFrom='web'):
    # Get name
    u = core.GetUserByID(uID)
    if not u:
        return {
            'code': -404,
            'message': 'User does not exist'
        }
    r = core.GetUserToken(uID)
    if accessedFrom != 'web':
        return ResponseAutoDeprecationWarning(apiversion, r['code'], uID=u.uID, message=r['message'], token=r['token'], name=u.name)
    return Res(r['code'], uID=u.uID, message=r['message'], token=r['token'], name=u.name)


@rmap.register_request('/register')
@Arg()
def register(uID, name, password, email):
    Log(uID, 'register', info={
        'name': name,
        'password': password,
        'email': email
    })
    return Res(**core.NewUser(uID, name, password, email))


@rmap.register_request('/getAuthStatus')
@authlib.authDec('verify_token')
@Arg()
def getAuthStatus(uID):
    u = core.GetUserByID(uID)
    if u:
        return {
            'code': 0,
            'message': 'Auth ok',
            'name': u.name,
            'uID': u.uID,
            'offline': u.offlineaccess
        }
    else:
        return {
            'code': -1,
            'message': 'Could not get name',
            'name': '',
            'uID': uID
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


@rmap.register_request('/getUIColorScheme')
@authlib.authDec('public')
@Arg()
def GetUIColorScheme(apiversion='0'):
    # [IMPORTANT] This is also the entry point of the program.
    r = core.GetUIColorScheme()
    return Res(code=0, message="Success", colorscheme=r)


@rmap.register_request('/getScript')
@authlib.authDec('public')
@Arg()
def GetScript(scriptID='', uID=None):
    Log(uID, 'getScript', info={
        'scriptID': scriptID
    })
    scriptContent = script.GetScriptByID(scriptID=scriptID)
    if scriptContent:
        return Res(code=0, message="Success", script=scriptContent)
    else:
        return Res(code=-1, message="The requested resource does not exist")


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


# Admin only - Logs access
@rmap.register_request('/getLogs')
@authlib.authDec('sudo_only')
@Arg()
def getLogs():
    ret = []
    for x in core.GetAllLogs():
        Q = dict(x.to_mongo())
        Q.pop('_id')
        if x['docID']:
            doc = core.GetDocByDocID(x['docID'])
            if doc:
                Q['documentName'] = doc.name
        ret.append(Q)
    return Res(0, logs=ret)


@rmap.register_request('/getLogsByUID')
@authlib.authDec('sudo_only')
@Arg()
def getLogsByUID(targetUID):
    ret = []
    for x in core.GetLogsByUID(targetUID):
        Q = dict(x.to_mongo())
        Q.pop('_id')
        if x['docID']:
            doc = core.GetDocByDocID(x['docID'])
            if doc:
                Q['documentName'] = doc.name
        ret.append(Q)
    return Res(0, logs=ret)


@rmap.register_request('/exam/newExam')
@authlib.authDec('exam_creation')
@Arg(maxTimeAllowed=float, name=str, maxAttemptsAllowed=int, examID=str, users=json.loads)
def newExam(uID, name, maxTimeAllowed, maxAttemptsAllowed=1, examID='', users='[]', docID=''):
    eID = core.newExam(name=name, createdBy=uID, maxTimeAllowed=maxTimeAllowed,
                       maxAttemptsAllowed=maxAttemptsAllowed, examID=examID, users=users, docID=docID)
    if eID:
        return Res(0, examID=eID)
    else:
        return Res(-1, 'Failed to create the exam')


@rmap.register_request('/exam/deleteExam')
@authlib.authDec('exam_write')
@Arg(examID=str)
def deleteExam(examID):
    exam = core.GetExamByExamID(examID=examID)
    if exam:
        if core.DeleteExamByExamID(examID=examID):
            return Res(0)
        return Res(-1, 'Failed to delete the exam')
    return Res(-701, 'Exam does not exist')


@rmap.register_request('/exam/editExam')
@authlib.authDec('exam_write')
@Arg(examID=str, properties=json.loads)
def editExam(uID, examID, properties='{}'):
    exam = core.GetExamByExamID(examID=examID)
    success = []
    failed = []

    if exam:
        for prop in properties:
            if prop in exam:
                setattr(exam, prop, properties[prop])
                success.append(prop)
            else:
                failed.append(prop)
            try:
                exam.save()
            except:
                return Res(-1, 'Failed to edit the exam')
        return Res(0, success=success, failed=failed)
    return Res(-701, 'Exam does not exist')


@rmap.register_request('/exam/getExamByExamID')
@authlib.authDec('exam_read')
@Arg(examID=str)
def getExamByID(uID, examID):
    exam = core.GetExamByExamID(examID=examID)
    if exam:
        exam = dict(exam.to_mongo())
        exam.pop('_id')
        exam['attemptsNum'] = len(
            core.GetUserExamAttempts(examID=exam['examID'], uID=uID))
        return Res(0, exam=exam)
    return Res(-701, 'Exam does not exist')


@rmap.register_request('/exam/getExamsByUID')
@authlib.authDec('verify_token')
@Arg(onlyAttemptable=StringBool)
def getExamsByUID(uID, onlyAttemptable='true'):
    exams = core.GetExamsByUID(uID, onlyAttemptable=onlyAttemptable)
    ret = []
    for exam in exams:
        exam = dict(exam.to_mongo())
        exam.pop('_id')
        exam['attemptsNum'] = len(
            core.GetUserExamAttempts(examID=exam['examID'], uID=uID))
        ret.append(exam)
    return Res(0, exams=ret)


@rmap.register_request('/exam/newAttempt')
@authlib.authDec('attempt_creation')
@Arg(examID=str, uID=str)
def newAttempt(examID, uID):
    exam = core.GetExamByExamID(examID=examID)
    if exam:
        attemptID = core.newAttempt(examID=examID, uID=uID)
        if attemptID:
            return Res(0, attemptID=attemptID)
        else:
            return Res(-1, 'Failed to create the attempt')


@rmap.register_request('/exam/deleteAttempt')
@authlib.authDec('attempt_write')
@Arg(attemptID=str)
def deleteAttempt(attemptID):
    attempt = core.GetExamAttemptByAttemptID(attemptID=attemptID)
    if attempt:
        if core.DeleteExamAttemptByAttemptID(attemptID=attemptID):
            return Res(0)
        return Res(-1, 'Failed to delete the attempt')
    return Res(-701, 'Attempt does not exist')


def AddExamInfoToAttempt(attemptDict: Dict) -> Dict:
    if 'examID' in attemptDict:
        exam = core.GetExamByExamID(attemptDict['examID'])
        if exam:
            attemptDict['exam'] = dict(exam.to_mongo())
            attemptDict['exam'].pop('_id')
        else:
            attemptDict['exam'] = {
                'examID': attemptDict['examID'],
                'name': '<DELETED EXAM>',
                'maxAttemptsAllowed': 0,
                'maxTimeAllowed': 0,
                'createdBy': '',
                'users': []
            }
    return attemptDict


@rmap.register_request('/exam/getAttemptByAttemptID')
@authlib.authDec('attempt_read')
@Arg(attemptID=str)
def getAttempt(attemptID):
    attempt = core.GetExamAttemptByAttemptID(attemptID=attemptID)
    if attempt:
        attempt = dict(attempt.to_mongo())
        attempt.pop('_id')
        return Res(0, attempt=AddExamInfoToAttempt(attempt))
    return Res(-701, 'Attempt does not exist')


@rmap.register_request('/exam/editAttempt')
@authlib.authDec('attempt_write')
@Arg(attemptID=str, properties=json.loads)
def editAttempt(attemptID, properties='{}'):
    if 'timeStarted' in properties or 'timeCompleted' in properties or 'completed' in properties:
        return Res(-400, 'For security reasons, you may not edit those properties')

    attempt = core.GetExamAttemptByAttemptID(attemptID=attemptID)
    success = []
    failed = []

    if attempt:
        for prop in properties:
            if prop in attempt:
                setattr(attempt, prop, properties[prop])
                success.append(prop)
            else:
                failed.append(prop)
            try:
                attempt.save()
            except:
                return Res(-1, 'Failed to edit the attempt')
        return Res(0, success=success, failed=failed)
    return Res(-701, 'Exam does not exist')


@rmap.register_request('/exam/finishAttempt')
@authlib.authDec('attempt_write')
@Arg(attemptID=str)
def finishAttempt(attemptID, docID=None):
    attempt = core.GetExamAttemptByAttemptID(attemptID=attemptID)
    if attempt:
        attempt.completed = True
        if docID:
            attempt.docID = docID
        attempt.timeCompleted = time.time()
        attempt.save()

        # Now, check for any resources that would be available to the user after the exam is finished
        exam = core.GetExamByExamID(attempt.examID)
        if exam:
            if len(core.GetUserExamAttempts(examID=attempt.examID, uID=attempt.uID)) >= exam.maxAttemptsAllowed:
                shared = []
                for docID in exam.resourcesAvailableAfterLastAttempt:
                    doc = core.GetDocByDocID(docID=docID)
                    if doc:
                        # if doc.owner == exam.createdBy:
                        # # No longer checks the ownership before sharing. This is to ensure that after the document is transferred to another account, the exam would still work as expected.
                        core.shareDocument(
                            targetUID=attempt.uID, docID=docID, read=True, write=False)
                        shared.append(docID)
                if len(shared) > 0:
                    return Res(1200, message='Successfully updated.', resources=shared, alert={
                        'title': f'{str(len(shared))} resources have been made available to you.',
                        'message': 'Thanks for attempting this exam. You now have the access to those resources. Please find them in the Library.'
                    })
        return Res(0, message='Successfully updated.')
    return Res(-701, 'Attempt does not exist')


@rmap.register_request('/exam/getExamAttemptsInProgress')
@authlib.authDec('verify_token')
@Arg()
def getExamAttemptsInProgress(uID):
    attempts = core.GetExamAttemptsInProgress(uID)
    ret = []
    for attempt in attempts:
        attempt = dict(attempt.to_mongo())
        attempt.pop('_id')
        ret.append(AddExamInfoToAttempt(attempt))
    return Res(0, attempts=ret)


@rmap.register_request('/exam/getExamAttemptsByUID')
@authlib.authDec('verify_token')
@Arg()
def getExamAttemptsByUID(uID, examID=None):
    attempts = core.GetUserExamAttempts(uID, examID=examID)
    ret = []
    for attempt in attempts:
        attempt = dict(attempt.to_mongo())
        attempt.pop('_id')
        ret.append(AddExamInfoToAttempt(attempt))
    return Res(0, attempts=ret)


@rmap.register_request('/log/appAbnormalExits')
@authlib.authDec('public')
@Arg(event=json.loads, timeReported=float)
def logAppAbnormalExits(timeReported='0', event='{}', uID='', token='', appSignature='', apiversion='0'):
    sig = authlib.auth('signature_check', kw={
        'uID': uID,
        'token': token,
        'appSignature': appSignature,
        'apiversion': apiversion
    })
    signature_status = True if sig['code'] == 0 else False
    log = AccessLog(uID=uID, time=timeReported, event="AppAbnormalExit", json={
        'report': event,
        'signature_status': signature_status,
        'apiversion': apiversion
    })
    try:
        log.save()
    except:
        return Res(-1, 'Failed to log the event')

    return Res(0, 'Succeeded')


@rmap.register_request('/sendToApp')
@authlib.authDec("verify_token")
@Arg()
def sendToApp(uID, docID):
    doc = core.GetDocByDocID(docID=docID)
    if not doc:
        return Res(-301, "Could not send to the app: Document does not exist.")
    return core.NewSendToAppRequest(uID=uID, docID=docID)


@rmap.register_request('/getSendToAppRequest')
@authlib.authDec("verify_token")
@Arg()
def getSendToAppRequest(uID):
    r = core.GetSendToAppRequests(uID=uID)
    if r:
        r = r.to_mongo()
        r.pop('_id')
    return Res(0, request=r)


@app.route('/appdirect/<path:path>')
def appDirect(path):
    return redirect("documentx://" + path, code=302)


@app.route('/batch', methods=['GET', 'POST'])
@Arg(batch=json.loads)
def batch_request(batch):
    return rmap.parse_batch(batch)


rmap.handle_flask(app)

if __name__ == '__main__':
    app.run(port=5001)

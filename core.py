from database import Document, me, User, Token
import time
import random
import hashlib
import base64
import secrets

Auths = {}
# MAX_TOKEN_AGE = 60*60*48 # 2 Days
MAX_TOKEN_AGE = 60*30 # 30 minutes - school use


def GetToken(uID):
    # [TODO]
    return 'test'


def GetUsernameByUID(uID):
    # [TODO]
    return 'Test account'


def NewDocument(name, subject, fileName, comments='', desc='', status='Recorded', docID=None):
    if docID and GetDocByDocID(docID):
        return -300, docID
    else:
        docID = str(int(time.time())) + secrets.token_urlsafe()[:5].lower()
    try:
        d = Document(name=name, docID=docID, subject=subject, status=status,
                     dScanned=time.time(), comments=comments, desc=desc, fileName=fileName)
        d.save()
    except me.errors.NotUniqueError:
        return -300, docID

    return 0, docID


def GetDocByDocID(docID):
    return Document.objects(docID=docID).first()


def SearchDocsByDocID(docID):
    return Document.objects(docID__icontains=docID)


def SearchDocsBySubject(subject):
    return Document.objects(subject__icontains=subject)


def SearchDocsByName(name):
    return Document.objects(name__icontains=name)


def DeleteDocs(docID):
    d = GetDocByDocID(docID)
    if not d:
        return False
    r = d.delete()
    return True if r == None else r


def GetUserByID(uID):
    u = User.objects(uID__iexact=uID).first()
    if u:
        return u
    return None


def GetUserToken(uID):
    u = GetUserByID(uID)
    if u:
        t = Token(created=time.time(), token=secrets.token_urlsafe(),
                  expires=time.time()+MAX_TOKEN_AGE)
        u.currentTokens.append(t)

        ct = 0
        for _ in range(len(u.currentTokens)):
            if u.currentTokens[ct].expires < time.time():
                u.currentTokens.pop(ct)
                # Remove expired token and don't update index
            else:
                ct += 1

        try:
            u.save()
            return {
                'code': 0,
                'message': 'Successfully got the token',
                'token': t.token
            }
        except:
            return {
                'code': -1,
                'message': 'Could not acquire token',
                'token': None
            }
    return {
        'code': -1,
        'message': 'Could not acquire token',
        'token': None
    }


def NewUser(uID, name, password):
    # Check if uID is unique
    if GetUserByID(uID):
        return {
            'code': -403,
            'message': 'User already exists'
        }
    try:
        u = User(uID=uID, name=name, password=password,
                 dRegistered=time.time())
        u.save()
        return {
            'code': 0,
            'message': 'Successfully registered.'
        }
    except:
        return {
            'code': -1,
            'message': 'Failed to register.'
        }


def GetDocuments():
    return Document.objects()


def GetAuthCode(docID):
    tok = secrets.token_urlsafe()
    if docID in Auths:
        Auths[docID][tok] = {
            'created': time.time()
        }
    else:
        Auths[docID] = {}
        Auths[docID][tok] = {
            'created': time.time()
        }
    return tok


def ValidatePermission(docID, auth):
    if docID in Auths:
        if auth in Auths[docID]:
            Auths[docID].pop(auth)
            return True
    return False

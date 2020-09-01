from database import Document, me, User, Token
import time
import random
import hashlib
import base64
import secrets
from mongoengine.queryset.visitor import Q


Auths = {}
# MAX_TOKEN_AGE = 60*60*48 # 2 Days
DEFAULT_MAX_TOKEN_AGE = 60*30  # 30 minutes - school use


def GetToken(uID):
    # [TODO]
    return 'test'


def GetUsernameByUID(uID):
    # [TODO]
    return 'Test account'


def NewDocument(name, subject, fileName, owner, comments='', desc='', status='Recorded', docID=None):
    if docID and GetDocByDocID(docID):
        return -300, docID
    else:
        docID = str(int(time.time())) + secrets.token_urlsafe()[:5].lower()
    try:
        d = Document(name=name, docID=docID, subject=subject, status=status,
                     dScanned=time.time(), comments=comments, desc=desc, fileName=fileName, owner=owner)
        d.save()
    except me.errors.NotUniqueError:
        return -300, docID

    return 0, docID


def GetDocByDocID(docID):
    return Document.objects(docID=docID).first()


def SearchDocsByDocID(docID, start=0, end=50):
    return Document.objects(docID__icontains=docID)[start:end]


def SearchDocsBySubject(subject, start=0, end=50):
    return Document.objects(subject__icontains=subject)[start:end]


def SearchDocsByName(name, start=0, end=50):
    return Document.objects(name__icontains=name)[start:end]


def GetTokenMaxAge(uID=None):
    if uID:
        u = GetUserByID(uID)
        if u:
            if u.tokenMaxAge:
                return u.tokenMaxAge
    return DEFAULT_MAX_TOKEN_AGE


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


def ArchiveDocument(docID):
    d = GetDocByDocID(docID)
    if d:
        try:
            d.archived = True
            d.save()
            return True
        except:
            return False
    return False


def SetTokenMaxAge(uID, MaxAge=None):
    u = GetUserByID(uID)
    try:
        if u:
            u.tokenMaxAge = MaxAge
            u.currentTokens = []
            # Reset all tokens
            u.save()
            return True
        return False
    except:
        return None


def GetUserToken(uID):
    u = GetUserByID(uID)
    if u:
        t = Token(created=time.time(), token=secrets.token_urlsafe(),
                  expires=time.time()+GetTokenMaxAge(uID))
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
                 dRegistered=time.time(), tokenMaxAge=DEFAULT_MAX_TOKEN_AGE)
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


def GetDocuments(uID=None, archived=False, start=0, end=50):
    'archived: None - Return All Documents; True - Only return archived; False - Only not archived.'
    if uID:
        # In the future, this should not only return documents which the uID owns but also display
        # document the uID have access to.
        if archived == None:
            return Document.objects(owner__iexact=uID).order_by('-dScanned')[start:end]
        return Document.objects(Q(owner__iexact=uID) & Q(archived=archived)).order_by('-dScanned')[start:end]

    # Currently allow guest access to the list of documents
    return Document.objects().order_by('-dScanned')


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

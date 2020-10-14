from database import Document, me, User, Token, ResourceGroup
import time
import random
import hashlib
import base64
import secrets
from mongoengine.queryset.visitor import Q


Auths = {}
# MAX_TOKEN_AGE = 60*60*48 # 2 Days
DEFAULT_MAX_TOKEN_AGE = 60*30  # 30 minutes - school use


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
    return Document.objects(docID__iexact=docID).first()


def GetUserHashTags(uID):
    HashTags = []
    for d in GetDocuments(uID, archived=None, start=0, end=0):
        for x in d.hashTags:
            if x not in HashTags:
                HashTags.append(x)
    return HashTags


def SearchDocsByDocID(uID, docID, start=0, end=50):
    if end == 0:
        return Document.objects(Q(docID__icontains=docID) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(docID__icontains=docID) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]


def SearchDocsBySubject(uID, subject, start=0, end=50):
    if end == 0:
        return Document.objects(Q(subject__icontains=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(subject__icontains=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]


def SearchDocsByHashTag(uID, hashTag, start=0, end=50):
    if end == 0:
        return Document.objects(Q(hashTags__icontains=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(hashTags__icontains=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]



def SearchDocsByName(uID, name, start=0, end=50):
    if end == 0:
        return Document.objects(Q(name__icontains=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(name__icontains=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]



def GetDocsBySubject(uID, subject, start=0, end=50):
    if end == 0:
        return Document.objects(Q(subject__iexact=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(subject__iexact=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]


def GetDocsByHashTag(uID, hashTag, start=0, end=50):
    if end == 0:
        return Document.objects(Q(hashTags__iexact=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(hashTags__iexact=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]



def GetDocsByName(uID, name, start=0, end=50):
    if end == 0:
        return Document.objects(Q(name__iexact=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))
    return Document.objects(Q(name__iexact=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end]



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

        # Check if end is 0. If it is, then there should not be a limit.
        if archived == None:
            if end == 0:
                return Document.objects(Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)).order_by('-dScanned')
            else:
                return Document.objects(Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)).order_by('-dScanned')[start:end]
        else:
            if end == 0:
                return Document.objects((Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)) & Q(archived=archived)).order_by('-dScanned')
            else:
                return Document.objects((Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)) & Q(archived=archived)).order_by('-dScanned')[start:end]

    return []


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


def GetResourceGroupByID(uID, resID):
    return ResourceGroup.objects(uID__iexact=uID, resID__iexact=resID).first()


def DeleteResourceGroupByID(uID, resID):
    r = GetResourceGroupByID(uID__iexact=uID, resID__iexact=resID)
    if r:
        try:
            r.delete()
            return True
        except:
            return False
    return False


def NewResourceGroup(uID, resID, name):
    if GetResourceGroupByID(uID, resID):
        return False

    try:
        r = ResourceGroup(uID=uID, resID=resID, name=name)
        r.save()
        return True
    except:
        return False


def EditResourceGroupByID(uID, resID, properties):
    r = GetResourceGroupByID(uID, resID)
    if r:
        try:
            for prop in properties:
                setattr(r, prop, properties[prop])
            r.save()
            return True
        except:
            return False
    return False

def GetResourceGroups(uID):
    return ResourceGroup.objects(uID__iexact = uID)

def GetDocumentsByResourceGroup(uID, resID):
    r = GetResourceGroupByID(uID, resID)
    if r:
        return r.documents
    return []

def AddDocumentToResourceGroup(uID, resID, docID):
    r = GetResourceGroupByID(uID, resID)
    if r:
        if docID not in r.documents:
            try:
                r.documents.append(docID)
                r.save()
                return True
            except:
                return False
        else:
            return True
    return False

def RemoveDocumentFromResourceGroup(uID, resID, docID):
    r = GetResourceGroupByID(uID, resID)
    if r:
        if docID not in r.documents:
            return True
        else:
            try:
                r.documents.remove(docID)
                r.save()
                return True
            except:
                return False

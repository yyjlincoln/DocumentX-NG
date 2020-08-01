from database import Document, me
import time
import random
import hashlib
import base64
import secrets

Auths = {}

def GetToken(uID):
    # [TODO]
    return 'test'

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
    return True if r==None else r


def GetDocuments():
    return Document.objects()

def GetAuthCode(docID):
    tok = secrets.token_urlsafe()
    if docID in Auths:
        Auths[docID][tok] = {
            'created':time.time()
        }
    else:
        Auths[docID] = {}
        Auths[docID][tok] = {
            'created':time.time()
        }
    return tok

def ValidatePermission(docID, auth):
    if docID in Auths:
        if auth in Auths[docID]:
            Auths[docID].pop(auth)
            return True
    return False
        

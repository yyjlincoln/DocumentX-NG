import re
import os
import unicodedata
from database import Document, me, User, Token, ResourceGroup, DocumentProperties, RemoteLoginRequest, AccessLog, Exam, ExamAttempt, Policy
import time
import random
import hashlib
import base64
import secrets
from mongoengine.queryset.visitor import Q
import json
import authlib
import emaillib.core
import emaillib.templates.general

# Color schemes
try:
    with open('colors.json') as f:
        COLORSCHEME = json.loads(f.read())
except:
    COLORSCHEME = {}


Auths = {}
# MAX_TOKEN_AGE = 60*60*48 # 2 Days
DEFAULT_MAX_TOKEN_AGE = 60*30  # 30 minutes - school use


def secure_filename(filename):
    # Modified from werkzeug.utils.secure_filename.
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
    filename = unicodedata.normalize("NFKD", filename)
    filename = filename.encode('utf-8', 'ignore').decode('utf-8')

    for sep in os.path.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, " ")
    _filename_ascii_strip_re = re.compile(r'[^A-Za-z0-9 _\u4E00-\u9FBF.-]')
    filename = str(_filename_ascii_strip_re.sub(
        "", filename)).strip("._")

    # on nt a couple of special files are present in each folder.  We
    # have to ensure that the target file is not such a filename.  In
    # this case we prepend an underline
    if (os.name == "nt" and filename and filename.split(".")[0].upper() in _windows_device_files):
        filename = f"_{filename}"

    return filename


def Log(uID=None, event=None, docID=None):
    r = AccessLog(uID=uID, event=event, docID=docID, time=time.time())
    r.save()
    for log in AccessLog.objects(time__lte=time.time()-1209600):
        # Clear any log that's more than 14 days
        log.delete()


def GetAllLogs():
    o = AccessLog.objects()
    return o


def GetLogsByUID(uID=''):
    return AccessLog.objects(uID__iexact=uID)


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
        return Document.objects(Q(docID__icontains=docID) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(docID__icontains=docID) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')[start:end]


def SearchDocsBySubject(uID, subject, start=0, end=50):
    if end == 0:
        return Document.objects(Q(subject__icontains=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(subject__icontains=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end].order_by('-dScanned')


def SearchDocsByHashTag(uID, hashTag, start=0, end=50):
    if end == 0:
        return Document.objects(Q(hashTags__icontains=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(hashTags__icontains=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID)))[start:end].order_by('-dScanned')


def SearchDocsByName(uID, name, start=0, end=50):
    if end == 0:
        return Document.objects(Q(name__icontains=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(name__icontains=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')[start:end]


def GetDocsBySubject(uID, subject, start=0, end=50):
    if end == 0:
        return Document.objects(Q(subject__iexact=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(subject__iexact=subject) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')[start:end]


def GetDocsByHashTag(uID, hashTag, start=0, end=50):
    if end == 0:
        return Document.objects(Q(hashTags__iexact=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(hashTags__iexact=hashTag) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')[start:end]


def GetDocsByName(uID, name, start=0, end=50):
    if end == 0:
        return Document.objects(Q(name__iexact=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')
    return Document.objects(Q(name__iexact=name) & (Q(owner__iexact=uID) | Q(policies__uID__iexact=uID))).order_by('-dScanned')[start:end]


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

def GetUserByEmail(uID):
    u = User.objects(email__iexact=uID).first()
    if u:
        return u
    return None


def GetDownloadName(docID, default='unknown'):
    r = GetDocByDocID(docID)
    if r:
        filename = secure_filename(
            r.name + '.' + r.fileName.rsplit('.', 1)[-1].lower())
    else:
        filename = default
    return filename


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


def clearRemoteLogin():
    s = RemoteLoginRequest.objects(created__lte=time.time()-120)
    for x in s:
        s.delete()


def NewRemoteLogin():
    s = secrets.token_hex(32)
    clearRemoteLogin()
    if not GetRemoteLogin(s):
        r = RemoteLoginRequest(rID=s, created=time.time())
        try:
            r.save()
        except:
            return None
        return s
    else:
        return None


def GetRemoteLogin(rID):
    return RemoteLoginRequest.objects(rID__iexact=rID).first()


def ApproveRemoteLogin(rID, uID, token):
    r = GetRemoteLogin(rID)
    if r:
        try:
            r.token = token
            r.uID = uID
            r.auth = 0
            r.save()
            return True
        except:
            return False
    else:
        return False


def RejectRemoteLogin(rID):
    r = GetRemoteLogin(rID)
    if r:
        try:
            r.delete()
            return True
        except:
            return False
    else:
        return False


def GetUserToken(uID, tokenMaxAge=None):
    u = GetUserByID(uID)
    if u:
        t = Token(created=time.time(), token=secrets.token_urlsafe(),
                  expires=time.time()+GetTokenMaxAge(uID) if tokenMaxAge == None else time.time()+tokenMaxAge)
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


def NewUser(uID, name, password, email):
    # Check if uID is unique
    if GetUserByID(uID):
        return {
            'code': -403,
            'message': 'User already exists'
        }
    # Hash and salt password, even though it'd already been hashed by the client (sha-256)
    salt = secrets.token_hex(32)
    password = hashlib.sha256(str(password+salt).encode('utf-8')).hexdigest()
    try:
        u = User(uID=uID, name=name, password=password,
                 dRegistered=time.time(), tokenMaxAge=DEFAULT_MAX_TOKEN_AGE, salt=salt, email=email)
        u.save()
        # emaillib.core.sendEmail(emaillib.templates.general.LinkEmail, email)
        # TODO: Write a secure mechanism to send the email and avoid spamming. Probably recaptcha?
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



def GetUIColorScheme():
    # Gets the colors for each document
    return COLORSCHEME


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

    # Since the redirection had been set up,
    # For all public documents, they'll all be redirected to /view?...
    # And that'll obtain an access token.
    # This check is temporarily disabled.

    # d = GetDocByDocID(docID)
    # if d:
    #     if d.accessLevel == 'public':
    #         # Public Document
    #         return True

    return False


def GetResourceGroupByID(uID, resID):
    return ResourceGroup.objects(uID__iexact=uID, resID__iexact=resID).first()


def DeleteResourceGroupByID(uID, resID):
    r = GetResourceGroupByID(uID, resID)
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
    return ResourceGroup.objects(uID__iexact=uID).order_by('-priority')


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


def GetDocumentProperties(uID, docID):
    r = DocumentProperties.objects(
        uID__iexact=uID, docID__iexact=docID).first()
    return r


def GetAllDocumentProperties(docID):
    r = DocumentProperties.objects(docID__iexact=docID)
    return r


def newExam(name, maxTimeAllowed, maxAttemptsAllowed=1, examID=None, createdBy=None, users=[], docID=''):
    if not examID:
        examID = secrets.token_hex(6)
    if GetExamByExamID(examID):
        return None
    try:
        e = Exam(maxTimeAllowed=maxTimeAllowed, name=name, maxAttemptsAllowed=maxAttemptsAllowed,
                 examID=examID, createdBy=createdBy, users=users, created=time.time(), docID=docID)
        e.save()
        return examID
    except Exception as e:
        print(e)
        return None


def DeleteExamByExamID(examID):
    e = GetExamByExamID(examID)
    if e:
        try:
            e.delete()
            return True
        except:
            return False
    return False


def DeleteExamAttemptByAttemptID(attemptID):
    e = GetExamAttemptByAttemptID(attemptID)
    if e:
        try:
            e.delete()
            return True
        except:
            return False
    return False


def GetExamByExamID(examID):
    return Exam.objects(examID__iexact=examID).first()


def GetExamAttemptByAttemptID(attemptID):
    return ExamAttempt.objects(attemptID__iexact=attemptID).first()


def GetExamsByUID(uID, onlyAttemptable=True):
    if onlyAttemptable:
        ret = []
        exams = Exam.objects(Q(users__iexact=uID) | Q(
            createdBy__iexact=uID)).order_by('-created')
        for exam in exams:
            if len(GetUserExamAttempts(uID, exam.examID)) < exam.maxAttemptsAllowed or exam.createdBy == uID:
                ret.append(exam)
        return ret
    else:
        return Exam.objects(Q(users__iexact=uID) | Q(createdBy__iexact=uID)).order_by('-created')


def GetUserExamAttempts(uID, examID=None):
    if examID:
        return ExamAttempt.objects(uID__iexact=uID, examID__iexact=examID).order_by('-timeStarted')
    else:
        return ExamAttempt.objects(uID__iexact=uID).order_by('-timeStarted')


def GetUnfinishedExamAttempts(uID, examID=None):
    if examID:
        return ExamAttempt.objects(uID__iexact=uID, examID__iexact=examID, completed=False)
    else:
        return ExamAttempt.objects(uID__iexact=uID, completed=False)


def GetExamAttemptsInProgress(uID, examID=None):
    ts = time.time()
    ret = []
    for attempt in GetUnfinishedExamAttempts(uID, examID):
        exam = GetExamByExamID(attempt.examID)
        if exam:
            if attempt.timeStarted + exam.maxTimeAllowed >= ts:
                ret.append(attempt)
    return ret


def newAttempt(uID, examID):
    attemptID = secrets.token_hex(6)
    try:
        e = ExamAttempt(uID=uID, examID=examID, attemptID=attemptID,
                        timeStarted=time.time(), completed=False)
        e.save()
        return attemptID
    except Exception as e:
        print(e)
        return None


def shareDocument(targetUID, docID, read=True, write=False):
    d = GetDocByDocID(docID)
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
            return {
                'code': 0,
                'result': {
                    'targetUID': targetUID,
                    'read': read,
                    'write': write
                }
            }
        except Exception as e:
            print(e)
            return {
                'code': -1,
                'message': 'Error'
            }

    return {
        'code': -1,
        'message': 'Error'
    }


def GetIfShareable(uID, docID):
    if not uID:
        # Prevents anonymous users from sharing
        return False

    if authlib._is_sudo(uID)['code'] == 0:
        return True

    u = GetUserByID(uID)
    d = GetDocByDocID(docID)
    # Checks the user role
    if u:
        if u.role == 'AppOnly' or u.role == 'ViewInAppOnly' or u.role == 'NoAppShare':
            return False
    # Checks the document accessLevel
    if d:
        if d.accessLevel == 'publicAppOnly' or d.accessLevel == 'privateAppOnly':
            return False

    # Checks the user's access to the document purely based on the document policy etc
    if authlib.doc_read(docID=docID, uID=uID, _internal_no_auth=True)['code'] == 0:
        return True

    return False

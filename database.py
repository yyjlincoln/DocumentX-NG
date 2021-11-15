import mongoengine as me


class Token(me.EmbeddedDocument):
    created = me.FloatField()
    expires = me.FloatField()
    token = me.StringField()

class Policy(me.EmbeddedDocument):
    uID = me.StringField(default=None)
    group = me.StringField(default=None)
    read = me.BooleanField(default=True)
    write = me.BooleanField(default=False)

class User(me.Document):
    name = me.StringField(required=True)
    uID = me.StringField(required=True, unique=True)
    role = me.StringField(default='User')
    dRegistered = me.FloatField(required=True)
    password = me.StringField(required=True)
    currentTokens = me.EmbeddedDocumentListField(Token, default=[])
    policies = me.EmbeddedDocumentListField(Policy, default=[])
    tokenMaxAge = me.FloatField()
    salt = me.StringField()
    email = me.EmailField(required=True)
    activated = me.BooleanField(default=False)
    offlineaccess = me.BooleanField(default=False)

class Document(me.Document):
    name = me.StringField(required=True)
    docID = me.StringField(required=True, unique=True)
    subject = me.StringField(required=True)
    status = me.StringField(default='Recorded')
    dScanned = me.FloatField(required=True)
    comments = me.StringField(default='')
    desc = me.StringField(default='')
    fileName = me.StringField(default='file')
    owner = me.StringField(required=True)
    policies = me.EmbeddedDocumentListField(Policy, default=[])
    accessLevel = me.StringField(default='private')  # private or public
    archived = me.BooleanField(default=False)
    hashTags = me.ListField(me.StringField(), default=[])

# TODO: Remove hashTags and archived from here, and place them in DocumentProperties so that each user can store different values.


class ResourceGroup(me.Document):
    resID = me.StringField()
    name = me.StringField()
    uID = me.StringField()
    documents = me.ListField(me.StringField(), default=[])
    priority = me.FloatField(default=0)


class DocumentProperties(me.Document):
    uID = me.StringField(required=True)
    docID = me.StringField(required=True)
    location = me.StringField(required=True)
# Location, hashTags


class RemoteLoginRequest(me.Document):
    rID = me.StringField(unique=True)
    uID = me.StringField()
    token = me.StringField()
    created = me.FloatField()
    auth = me.IntField(default=1)
    # 0 - Auth success
    # 1 - Not auth / scan yet
    # 2 - Scanned, not auth

class AccessLog(me.Document):
    uID = me.StringField()
    event = me.StringField()
    docID = me.StringField()
    time = me.FloatField()
    json = me.DictField()


class Exam(me.Document):
    examID = me.StringField(required=True, unique=True)
    name = me.StringField(required=True)
    maxTimeAllowed = me.FloatField(required=True) # in seconds
    maxAttemptsAllowed = me.IntField(required=True, default = 1)
    createdBy = me.StringField(required=True)
    users = me.ListField(me.StringField(), default=[])
    created = me.FloatField(required=True)
    docID = me.StringField(default='')
    resourcesAvailableAfterLastAttempt = me.ListField(me.StringField(), default=[])

class ExamAttempt(me.Document):
    attemptID = me.StringField(required=True, unique=True)
    examID = me.StringField(required=True)
    uID = me.StringField(required=True)
    timeStarted = me.FloatField(required=True)
    completed = me.BooleanField(default=False)
    timeCompleted = me.FloatField()
    docID = me.StringField() # Exam attempt file
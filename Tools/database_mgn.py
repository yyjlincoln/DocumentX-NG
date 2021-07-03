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


me.connect('documentx')


import mongoengine as me

class Token(me.EmbeddedDocument):
    created = me.FloatField()
    expires = me.FloatField()
    token = me.StringField()

class Policy(me.EmbeddedDocument):
    user = me.StringField(default=None)
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
    accessLevel = me.StringField(default = 'private') # private or public


conn = me.connect('documentx')

# Code here
for x in User.objects():
    x.policies = []
    x.save()
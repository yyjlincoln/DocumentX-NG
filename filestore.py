import io
import os

FILESTORAGE = '/etc/docx/fs'

def newSrorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)

def getStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)
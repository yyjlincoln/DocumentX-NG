import io
import os

FILESTORAGE = '/etc/docx/fs'

def newStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)

def getStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)
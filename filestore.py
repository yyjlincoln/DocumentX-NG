import io
import os

FILESTORAGE = '/applications/documentx-storage'

def newStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)

def getStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)
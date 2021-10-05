from s3gateway import gateway, Gateway
import os

gateway: Gateway

CACHE_PATH = '/tmp/documentx'

def saveFile(docID, content):
    gateway.uploadFile(docID, content)

def renameFile(docID, newID) -> bool:
    # oldPath = getStorageLocation(docID)
    # newPath = getStorageLocation(newID)
    # try:
    #     os.rename(oldPath, newPath)
    #     return True
    # except:
    #     return False
    raise Exception("Not implemented")

def deleteFile(docID):
    gateway.deleteFile(docID)

def getFileLink(docID):
    return gateway.getURL(docID, expiresIn=30)

def getStorageLocation(docID):
    path = os.path.join(CACHE_PATH, docID)
    if os.path.exists(path) and os.path.isfile(path):
        return path
    if gateway.downloadFile(docID, path):
        return path
    else:
        raise Exception("File not found")

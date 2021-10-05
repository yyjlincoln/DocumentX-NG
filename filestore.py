from s3gateway import gateway, Gateway
import os
import threading
import time

gateway: Gateway

CACHE_PATH = '/tmp/documentx'


def uploadFileFromCache(docID):
    with open(os.path.join(CACHE_PATH, docID), 'rb') as f:
        if gateway.uploadFile(docID, f.read()):
            os.remove(os.path.join(CACHE_PATH, docID + '.uploading'))
        else:
            with open(os.path.join(CACHE_PATH, docID + '.uploadfailure'), 'w') as f:
                f.write(str(time.time()))

def saveFile(docID, content):
    with open(os.path.join(CACHE_PATH, docID), 'wb') as f:
        f.write(content)
    with open(os.path.join(CACHE_PATH, docID + '.uploading'), 'w') as f:
        f.write(str(time.time()))
    t = threading.Thread(target=uploadFileFromCache, args=(docID,))
    t.start()
    return True


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

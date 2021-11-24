from s3gateway import gateway, Gateway
import os
import threading
import time
import json

gateway: Gateway

CACHE_PATH = '/etc/documentx'
with open('secrets.json') as f:
    config = json.load(f)
    if 'cache' in config:
        CACHE_PATH = config['cache']

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
    try:
        os.remove(os.path.join(CACHE_PATH, docID))
    except:
        pass


def getFileLink(docID):
    return gateway.getURL(docID, expiresIn=30)


def getStorageLocation(docID):
    path = os.path.join(CACHE_PATH, docID)
    # Clears cache
    clearCache(docID)
    if os.path.exists(path) and os.path.isfile(path):
        return path
    if gateway.downloadFile(docID, path):
        return path
    else:
        raise Exception("File not found")


def clearCache(docID):
    if len(listFiles(CACHE_PATH)) > 100:
        files = listFiles(CACHE_PATH)
        clean = []
        avoid = [docID]

        for name in files:
            # Get uploading and uploadfailure files
            if name.endswith('.uploading'):
                avoid.append(name)
                avoid.append(name[:-10])
            elif name.endswith('.uploadfailure'):
                avoid.append(name)
                avoid.append(name[:-14])

        for name in files:
            if name not in avoid:
                os.remove(os.path.join(CACHE_PATH, name))


def listFiles(path) -> list:
    files = []
    for name in os.listdir(path):
        if os.path.isfile(os.path.join(path, name)):
            files.append(name)
    return files

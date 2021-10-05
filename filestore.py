import io
import os

FILESTORAGE = '/etc/docx/fs'

def newStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)

def getStorageLocation(docID):
    return os.path.join(FILESTORAGE, docID)

def saveFile(docID, content):
    path = newStorageLocation(docID)
    try:
        with open(path, 'wb') as f:
            f.write(content)
        return True
    except:
        return False


def renameFile(docID, newID) -> bool:
    oldPath = getStorageLocation(docID)
    newPath = getStorageLocation(newID)
    try:
        os.rename(oldPath, newPath)
        return True
    except:
        return False

def deleteFile(docID):
    path = getStorageLocation(docID)
    if os.path.exists(path) and os.path.isfile(path):
        try:
            os.remove(path)
            return True
        except:
            return False
    
import getpass
import zmail
import time
import requests
import io
from config import Config
import base64
import hashlib

server = zmail.server(Config['email.email'], Config['email.password'])

# server.get_mails()
token = ''


uID = input('Please input your uID:')

pHash = hashlib.sha256(getpass.getpass(
    'Enter password:').encode()).hexdigest()


def GetToken(uID, pHash):
    try:
        r = requests.post('https://apis.mcsrv.icu/login', {
            'uID': uID,
            'password': pHash
        }).json()
        if r['code'] == 0:
            token = r['token']
            return token
        else:
            print('Unable to authenticate with the server: ', r)
            return False
    except Exception as e:
        print('Unable to authentiacte with the server due to an Python internal error:', e)
        return False


def PostFile(fStream):
        # POST to the server
    return requests.post('https://apis.mcsrv.icu/uploadDocument', data={
        'name': subject,
        'subject': 'Unspecified',
        'comments': 'This record is automatically created by DocumentX Gmail Integration.',
        'token': token,
        'uID': uID
    }, files={
        'file': fStream
    }).json()


token = GetToken(uID, pHash)
if token:
    print('Started.')
else:
    print('Authentication failed.')
    exit()

while True:
    try:
        d = server.get_latest()
        if len(d['attachments']) == 1:
            fileName, fData = d['attachments'][0]
            subject = d['subject']
            # Create a Stream
            fStream = io.BytesIO(fData)
            fStream.name = fileName
            # Post file
            r = PostFile(fStream)
            if r['code'] == 0:
                print('Successfully uploaded file #'+str(r['docID']))
            elif r['code'] == -406 or r['code']==-405:
                print('Token has expired! Getting token...')
                token = GetToken(uID, pHash)
                print('Retrying...')
                fStream.seek(0)
                r = PostFile(fStream)
                if r['code'] == 0:
                    print('Successfully uploaded file #'+str(r['docID']))
                else:
                    print('Failed to upload file', r)

    except Exception as e:
        print('Could not get email.',e)
    finally:
        time.sleep(30)

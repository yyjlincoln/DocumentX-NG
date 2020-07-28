import zmail
import time
import requests
import io
from werkzeug.utils import secure_filename
from config import Config

server = zmail.server(Config['email.email'],Config['email.password'])

# server.get_mails()

while True:
    try:
        d = server.get_latest()
        if len(d['attachments']) == 1:
            fileName, fData = d['attachments'][0]
            subject = d['subject']
            # Create a Stream
            fStream = io.BytesIO(fData)
            fStream.name=fileName
            # POST to the server
            r = requests.post('https://apis.mcsrv.icu/uploadDocument', data={
                'name': subject,
                'subject': 'Unspecified',
                'comments': 'This record is automatically created by DocumentX Gmail Integration.'
            }, files={
                'file': fStream
            })
            print(r.json())
    except Exception as e:
        print('Could not get email.')
    finally:
        time.sleep(30)

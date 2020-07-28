import zmail
import time
import requests
import io
from werkzeug.utils import secure_filename
from config import Config
import base64

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

            status = 'Failed'
            DocID = 'unknown'
            try:
                r = r.json()
                status = r['message'] + ' ('+str(r['code'])+')'
                DocID = r['docID']
            except Exception as e:
                status = 'Failed ('+ str(e) + ')'
            
            htmlContent = f'''
            <p><b>File {fileName} has been scanned.</b></p>
            <p>{status}</p>
            <p></p>
            <p>DocID: {DocID}</p>
            <p>Link: <a href="https://apis.mcsrv.icu/viewDocumentByID?docID={DocID}">here</a></p>
            <img src="https://apis.mcsrv.icu/qr?urlEncoded={base64.b64encode(str(f'https://apis.mcsrv.icu/viewDocumentByID?docID={DocID}').encode()).decode()}"></img>
            <p></p>
            <p>This is an automated email from DocumentX-GmailIntegration.</p>
            '''
            try:
                server.send_mail(Config['email.reciept'],{
                    'subject':f'File {fileName} has been scanned.',
                    'content_html':htmlContent
                })
            except Exception as e:
                print('Could not send email reciept: '+str(e))

    except Exception as e:
        print('Could not get email.')
    finally:
        time.sleep(30)

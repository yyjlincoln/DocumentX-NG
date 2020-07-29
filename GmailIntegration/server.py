import zmail
import time
import requests

server = zmail.server('automated.yan@gmail.com','XgS7jxM3gaP13aVUhXZ5Rg==')

# server.get_mails()

while True:
    try:
        d = server.get_latest()
        if len(d['attachments'])==1:
            fileName, fData = d['attachments'][0]
            subject = d['subject']
            # POST
            print({
                'name':subject,
                'subject':'Unspecified',
                'comments':'This record is automatically created by DocumentX Gmail Integration.'
            })
            requests.post('https://apis.mcsrv.icu/upload',data={
                'name':subject,
                'subject':'Unspecified',
                'comments':'This record is automatically created by DocumentX Gmail Integration.'
            }, files = {
                fileName: fData
            })
        time.sleep(30)
    except:
        print('Could not get email.')
        time.sleep(30)
        continue

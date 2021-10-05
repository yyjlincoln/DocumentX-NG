import boto3
import boto3.session
import os

class Gateway():
    def __init__(self, key, secret) -> None:
        session = boto3.session.Session()
        self.client = session.client('s3',
                                     region_name='nyc3',
                                     endpoint_url='https://nyc3.digitaloceanspaces.com',
                                     aws_access_key_id=key,
                                     aws_secret_access_key=secret)

    def uploadFile(self, filename: str, body: bytes):
        s = self.client.put_object(Bucket='documentx',
                                   Key=filename,
                                   Body=body,
                                   ACL='private')
        return s['ResponseMetadata']['HTTPStatusCode'] == 200

    def getURL(self, filename: str, expiresIn: int = 300):
        url = self.client.generate_presigned_url(ClientMethod='get_object',
                                                 Params={'Bucket': 'documentx',
                                                         'Key': filename},
                                                 ExpiresIn=expiresIn)

        return url

    def deleteFile(self, filename: str):
        s = self.client.delete_object(Bucket='documentx',
                                      Key=filename)
        return s['ResponseMetadata']['HTTPStatusCode'] == 204

    def listFiles(self):
        response = self.client.list_objects(Bucket='documentx')
        keys = []
        if 'Contents' in response:
            for obj in response['Contents']:
                keys.append(obj['Key'])
        return keys
    
    def downloadFile(self, filename: str, path):
        try:
            self.client.download_file('documentx',
                        filename,
                        path)
            return True
        except Exception as e:
            print(e)
            return False
        


    # def renameFile(self, oldName: str, newName: str):
    #     s = self.client.copy_object(Bucket='documentx',
    #                                 CopySource=oldName,     
    #                                 Key=newName,
    #                                 ACL='private')
    #     self.deleteFile(oldName)
    # it's not working properly

import json
import os

try:
    with open('secrets.json') as f:
        config = json.loads(f.read())
        key = config['key']
        secret = config['secret']
except Exception as e:
    # Please create a secrets.json file with the following content: \n\n{ "key": "your_key", "secret": "your_secret", "endpoint": "your_endpoint" }
    raise PermissionError('Could not load the keys. Please create a secrets.json file with the following content: \n\n{ "key": "your_key", "secret": "your_secret", "endpoint": "your_endpoint" }', e)

gateway = Gateway(key, secret)

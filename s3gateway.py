import json
from typing import IO
import boto3
import boto3.session
import os
import io


class Gateway():
    def __init__(self, key: str, secret: str) -> None:
        session = boto3.session.Session()
        self.client = session.client('s3',
                                     region_name='nyc3',
                                     endpoint_url='https://s3.g.s4.mega.io',
                                     aws_access_key_id=key,
                                     aws_secret_access_key=secret)

    def uploadFile(self, filename: str, body: bytes, bucket='documentx') -> bool:
        s = self.client.put_object(Bucket=bucket,
                                   Key=filename,
                                   Body=body,
                                   ACL='private')
        return s['ResponseMetadata']['HTTPStatusCode'] == 200

    def uploadFileObj(self, filename: str, obj: IO, bucket='documentx') -> bool:
        try:
            s = self.client.upload_fileobj(obj, Bucket=bucket,
                                           Key=filename,
                                           ExtraArgs={'ACL': 'private'})
            return True
        except:
            return False

    def getURL(self, filename: str, expiresIn: int = 300, bucket='documentx') -> str:
        url = self.client.generate_presigned_url(ClientMethod='get_object',
                                                 Params={'Bucket': bucket,
                                                         'Key': filename},
                                                 ExpiresIn=expiresIn)

        return url

    def deleteFile(self, filename: str, bucket='documentx') -> bool:
        s = self.client.delete_object(Bucket=bucket,
                                      Key=filename)
        return s['ResponseMetadata']['HTTPStatusCode'] == 204

    def listFiles(self, bucket='documentx') -> list:
        response = self.client.list_objects(Bucket=bucket)
        keys = []
        if 'Contents' in response:
            for obj in response['Contents']:
                keys.append(obj['Key'])
        return keys

    def downloadFile(self, filename: str, path: str, bucket='documentx') -> bool:
        try:
            self.client.download_file(bucket,
                                      filename,
                                      path)
            return True
        except Exception as e:
            print(e)
            return False

    def downloadFileObj(self, filename: str, ioObj: io.BytesIO, bucket='documentx') -> bool:
        try:
            self.client.download_fileobj(Bucket=bucket,
                                         Key=filename,
                                         Fileobj=ioObj)
            return True
        except Exception as e:
            print(e)
            return False


try:
    with open('secrets.json') as f:
        config = json.loads(f.read())
        key = config['key']
        secret = config['secret']
except Exception as e:
    # Please create a secrets.json file with the following content: \n\n{ "key": "your_key", "secret": "your_secret", "endpoint": "your_endpoint" }
    raise PermissionError(
        'Could not load the keys. Please create a secrets.json file with the following content: \n\n{ "key": "your_key", "secret": "your_secret", "endpoint": "your_endpoint" }', e)

gateway = Gateway(key, secret)

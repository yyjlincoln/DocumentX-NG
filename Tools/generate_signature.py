import time
import hashlib
import json
import logging

try:
    with open('secrets.json') as f:
        secrets = json.loads(f.read())
        APP_SECRET = secrets['app_secret']
except Exception as e:
    logging.fatal('Could not load secrets due to the following exception:')
    raise e


def calculate(uID = 'developer', token = '', apiversion = '0'):
    ts = int(time.time())
    if apiversion in APP_SECRET:
        return hashlib.sha256(str(uID.lower(
            ) + token.lower() + str(ts - ts % 10) + APP_SECRET[apiversion]).encode(encoding='utf-8')).hexdigest()


def calculate_developer_signature(status='on',apiversion='0'):
    return 'documentx://dev/'+status+'/'+calculate('developer', '', apiversion)

print(calculate_developer_signature(apiversion='1.0.0', status='off'))
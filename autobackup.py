from database import User, Document, ResourceGroup, DocumentProperties, AccessLog, Exam, ExamAttempt
import time
from secrets import token_hex
from mongoengine import connect
from s3gateway import gateway
import os


connect('documentx')

BACKUP = {
    "User": User,
    "Document": Document,
    "ResourceGroup": ResourceGroup,
    "DocumentProperties": DocumentProperties,
    "AccessLog": AccessLog,
    "Exam": Exam,
    "ExamAttempt": ExamAttempt
}

# Backup Structure:
# METADATA
#   Key and value, separated by "=" 
#   Must contain field "separator=xxxxxxxxx...xxx"
#   Each key-value pair is separated by "\n"
# \r\n\r\n
# DATA
#   Each object in the database, separated by \n==<separator>==\n

backuptime = str(int(time.time()))

# Do not upload yet to make sure the backup is captured in the shortest amount of time
for kind in BACKUP:
    # Not using JSON. If the database is big enough, this would use too much memory and cause issues.
    # Also, this practices my skills of data structures.

    fname = "Backup-"+backuptime+'-'+kind
    with open(fname, 'w') as f:
        # Write metadata
        separator = token_hex(16)
        f.write('created='+str(time.time())+'\n')
        f.write('separator='+separator+'\n')
        f.write('database='+kind+'\n')
        f.write('\r\n\r\n')
        for item in BACKUP[kind].objects():
            f.write(item.to_json())
            f.write('\n=='+separator+'==\n')

# After the backup is created, upload them
for kind in BACKUP:
    fname = "Backup-"+backuptime+'-'+kind
    with open(fname, 'rb') as f:
        # Upload to S3
        result = gateway.uploadFile(fname, f.read(), bucket='documentx-backups')
        if result:
            print("Backup for kind ",kind,'at',backuptime,'was complete.')
            os.remove(fname)

from database import User
from flask import jsonify, request
import inspect
from functools import wraps
import core
import time
import logging
from utils.ResponseModule import Res
from utils.AutoArguments import Arg
import hashlib
import json

try:
    with open('secrets.json') as f:
        secrets = json.loads(f.read())
        APP_SECRET = secrets['app_secret']
except Exception as e:
    logging.fatal('Could not load secrets due to the following exception:')
    raise e


class JITDictionary(object):
    '''
    A pseudo-dictionary that overwrites its setter and getter.
    This allows the values of the dictionary to be fetched just-in-time when the setter is called.
    '''

    def __init__(self, read_from=None, commit_changes_to=None):
        self.read_from = read_from
        self.commit_changes_to = commit_changes_to

    def __setitem__(self, key, value) -> None:
        if callable(self.commit_changes_to):
            self.commit_changes_to(key, value)
        else:
            logging.warn('There is nowhere to commit the value!')
            raise RuntimeError('No commit_changes_to handler is provided.')

    def __getitem__(self, key):
        if callable(self.read_from):
            return self.read_from(key)
        else:
            logging.warn('There is nowhere to read any data from.')
            raise IndexError('read_from handler had not been provided.')

    def __contains__(self, key) -> bool:
        if callable(self.read_from):
            if self.read_from(key) == None:
                return False
            else:
                return True
        else:
            logging.warn(
                'IN Operator is performed while no read_from is provided.')
            return False


class Operation():
    class SkipAll(object):
        def __init__(self, obj={}):
            self.obj = obj

        def __getitem__(self, name):
            return self.obj.__getitem__(name)

        def __setitem__(self, name, value):
            return self.obj.__setitem__(name, value)

    pass

# TODO Token management & Complete User Auth


def ReturnHandler(code, message, as_decorator=False, **kw):
    r = {
        'code': code,
        'message': message
    }
    r.update(kw)

    if as_decorator:
        return jsonify(r)
    else:
        return r


def document_access_log(docID, uID=None, accessedFrom='web'):
    core.Log(uID, 'access.document:'+accessedFrom, docID=docID)
    return {
        'code': 0,
        'message': 'Lodged.'
    }


def _password(uID, password, accessedFrom='web'):
    u = core.GetUserByID(uID)
    if u:
        if u.password == password:
            core.Log(uID=uID, event='password-login.success:'+accessedFrom)
            return {
                'code': 0,
                'uid': u.uID,
                'message': 'success'
            }
    core.Log(uID=uID, event='password-login.failed-attempt:'+accessedFrom)
    return {
        'code': -400,
        'message': 'Authentication failed.'
    }


def auth(level='verify_token', kw={}):
    # Map the level to the corresponding verifying method
    if level not in levels:
        raise Exception('Authentication method is not defined')

    # Now get all arguments required by the handlers
    HandlerArgs = {}

    for _hand in levels[level]:
        Arg = inspect.getargspec(_hand)
        Needed = Arg.args[:-len(Arg.defaults)] if Arg.defaults else Arg.args
        Optional = dict(zip(
            Arg.args[-len(Arg.defaults if Arg.defaults else []):], Arg.defaults if Arg.defaults else []))
        HandlerArgs[_hand] = {
            'needed': Needed,
            'optional': Optional
        }

    for _hand in HandlerArgs:
        _handarg = {}
        for _par in HandlerArgs[_hand]['needed']:
            if _par not in kw:
                return ReturnHandler(-402, f'Authentication could not be completed because argument {_par} does not exist')
            _handarg[_par] = kw[_par]
        for _par in HandlerArgs[_hand]['optional']:
            if _par in kw:
                _handarg[_par] = kw[_par]

        # Call auth
        result = _hand(**_handarg)
        if isinstance(result, Operation.SkipAll):
            return ReturnHandler(0, 'Authentication was successful. (SkipAll)')
        elif result['code'] != 0:
            return ReturnHandler(**result)

    return ReturnHandler(0, 'Authentication was successful.')


def authDec(level='', **kw):
    if level not in levels:
        raise Exception('Authentication method is not defined')

    # Now get all arguments required by the handlers
    HandlerArgs = {}

    for _hand in levels[level]:
        Args = inspect.getargspec(_hand)
        Needed = Args.args[:-len(Args.defaults)
                           ] if Args.defaults else Args.args
        Optional = dict(zip(
            Args.args[-len(Args.defaults if Args.defaults else []):], Args.defaults if Args.defaults else []))
        HandlerArgs[_hand] = {
            'needed': Needed,
            'optional': Optional
        }

    def decorator(func):
        @wraps(func)
        @Arg()
        def _i(__fetch_values, __channel, *args, **kw):

            funckw = JITDictionary(read_from=__fetch_values)

            Result = auth(level=level, kw=funckw)
            if Result['code'] == 0:
                # This will also pass through the __channel and __fetch_args as for the callee function:
                # - It will invoke another GetArgs(), and those two arguments are already extracted from **kw
                # hence it will need to be separately passed on to the callee function for GetArgs to work as expected.
                return func(*args, __fetch_values=__fetch_values, __channel=__channel, **kw)
            else:
                return Res(**Result)
        return _i
    return decorator


def _test_allow():
    return {
        'code': 0,
        'message': '(_test_allow)'
    }


def _test_single_token(uID, token):
    if token == 'test':
        return {
            'code': 0,
            'message': 'test_token'
        }
    return {
        'code': -400,
        'message': 'Invalid token (testing)'
    }
    # pass


def download_ua_check():
    ua = request.headers.get('User-Agent')
    UA_NOT_COMPATIBLE = {'MicroMessenger/': {
        'code': -501,
        'message': '请在浏览器中打开本页面。'
    }, 'QQ/': {
        'code': -502,
        'message': '请在浏览器中打开本页面。'
    }}

    if ua:
        for x in UA_NOT_COMPATIBLE:
            if x in ua:
                return UA_NOT_COMPATIBLE[x]
    return {
        'code': 0,
        'message': 'UA Check OK'
    }


def doc_access_v_token(uID=None, token=None):
    if uID and token:
        return v_token(uID, token)
    return {
        'code': -401,
        'message': 'Sign in is required.'
    }


def doc_read(docID=None, uID=None, token=None):
    if docID:
        d = core.GetDocByDocID(docID)
        if d:
            if d.accessLevel == 'public' or d.accessLevel == 'publicAppOnly':
                return {
                    'code': 0,
                    'message': 'Public Document'
                }
            else:
                # Not public - auth
                authresult = doc_access_v_token(uID, token)
                if authresult['code'] != 0:
                    return authresult
                # Check permission
                if str(d.owner.lower()) == str(uID).lower():
                    return {
                        'code': 0,
                        'message': 'Document owner'
                    }
                else:
                    for x in d.policies:
                        if str(x.uID).lower() == str(uID).lower() and x.read == True:
                            return {
                                'code': 0,
                                'message': 'Policy allowed'
                            }
                    return {
                        'code': -400,
                        'message': 'You do not have the right to access this document.'
                    }
    return {
        'code': -301,
        'message': 'Document does not exist'
    }


def doc_write(docID=None, uID=None, token=None):
    if docID:
        d = core.GetDocByDocID(docID)
        if d:
            # if d.accessLevel == 'public':
            #     return {
            #         'code': 0,
            #         'message': 'Public Document'
            #     }
            # else:

            # Not public - auth
            authresult = doc_access_v_token(uID, token)
            if authresult['code'] != 0:
                return authresult
            # Check permission
            if str(d.owner.lower()) == str(uID).lower():
                return {
                    'code': 0,
                    'message': 'Document owner'
                }
            else:
                for x in d.policies:
                    if str(x.uID).lower() == str(uID).lower() and x.write == True:
                        return {
                            'code': 0,
                            'message': 'Policy allowed'
                        }
                return {
                    'code': -400,
                    'message': 'You do not have the right to make changes to this document.'
                }
    return {
        'code': -301,
        'message': 'Document does not exist'
    }


def v_token(uID, token):
    u = core.GetUserByID(uID)
    if u:
        for x in u.currentTokens:
            if x.token == token:
                if x.expires > time.time():
                    return {
                        'code': 0,
                        'message': 'Token validation success'
                    }
                else:
                    return {
                        'code': -406,
                        'message': 'Token has expired'
                    }

    return {
        'code': -405,
        'message': 'Token validation failed'
    }


def rolecheck(uID=None, token=None):
    if not uID or not token:
        return {
            'code': 0,
            'message': 'token verification failed - continue'
        }
    # Check login stat
    if uID and token:
        r = v_token(uID, token)
        if r['code'] != 0:
            # Invalid login state
            return {
                'code': 0,
                'message': 'Not sudo - login verification failed'
            }

        u = core.GetUserByID(uID)
        if u:
            if u.role == 'sudo' or u.role == 'root':
                return Operation.SkipAll({
                    'code': 1001,
                    'message': 'Sudo user'
                })
    return {
        'code': 0,
        'message': 'Sudo check - not sudo'
    }


def v_upload_permissions(uID):
    u = core.GetUserByID(uID)
    if u:
        if u.role != 'demo' and u.role != 'temp' and u.role != 'noupload':
            return {
                'code': 0,
                'message': 'Upload right validation succeed'
            }
    return {
        'code': -400,
        'message': 'You do not have the right to upload a document.'
    }


def calculateAcceptableSignatures(uID, token):
    ts = int(time.time())
    signatures = []
    # Acceptable time ranges: +- 10 seconds
    for x in [ts - ts % 10 - 10, ts - ts % 10, ts + ts % 10]:
        signatures.append(hashlib.sha256(str(uID.lower(
        ) + token.lower() + str(x) + APP_SECRET).encode(encoding='utf-8')).hexdigest())
    return signatures


def is_app_required_check(uID='', token='', accessedFrom='web', appSignature=''):
    if not uID:
        # This should be fine, as any sensitive api will require auth and hence uID will not be ''
        return {
            'code': 0,
            'message': 'Warning: Skipping is_app_required check'
        }
    u = core.GetUserByID(uID)
    if u:
        if u.role == 'AppOnly':
            if accessedFrom.split('/')[0] != 'DocumentXAccess':
                return {
                    'code': -600,
                    'message': 'Please upgrade your app to the latest version from TestFlight.'
                }
            if appSignature not in calculateAcceptableSignatures(uID, token):
                return {
                    'code': -601,
                    'message': 'Invalid or empty signature.'
                }

            return {
                'code': 0,
                'message': 'Accessing from the App'
            }

        else:
            return {
                'code': 0,
                'message': 'Access is permitted.'
            }
    else:
        return {
            'code': -404,
            'message': 'User does not exist'
        }


def document_access_app_check(uID='', token='', accessedFrom='web', appSignature='', docID=''):
    if docID:
        if core.GetDocByDocID(docID).accessLevel == 'publicAppOnly' or core.GetDocByDocID(docID).accessLevel == 'privateAppOnly':
            
            if accessedFrom.split('/')[0] != 'DocumentXAccess':
                return {
                    'code': -600,
                    'message': 'This document may only be accessed in the DocumentX App.'
                }

            if appSignature not in calculateAcceptableSignatures(uID, token):
                return {
                    'code': -601,
                    'message': 'Invalid or empty signature.'
                }
            
    return {
        'code': 0,
        'message': 'Access is permitted.'
    }
        



def deny_all():
    return {
        'code': -400,
        'message': 'Access is denied: Insufficient permissions.'
    }


levels = {
    'document_access': [document_access_log, rolecheck, doc_read, is_app_required_check, document_access_app_check],
    'document_download': [document_access_log, download_ua_check, rolecheck, doc_read, is_app_required_check, document_access_app_check],
    'doc_read': [rolecheck, doc_read, is_app_required_check],
    'doc_write': [rolecheck, doc_write, is_app_required_check],
    'verify_token': [v_token, is_app_required_check],
    'login': [_password, is_app_required_check],
    'verify_upload': [rolecheck, v_token, v_upload_permissions, is_app_required_check],
    'elevated': [_password, v_token, is_app_required_check],
    'sudo_only': [rolecheck, deny_all]
}

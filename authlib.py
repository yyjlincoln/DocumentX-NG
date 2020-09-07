from database import User
from flask import request, jsonify
import inspect
from functools import wraps
import core
import time


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


def _password(uID, password):
    u = core.GetUserByID(uID)
    if u:
        if u.password == password:
            return {
                'code': 0,
                'uid': u.uID,
                'message': 'success'
            }
    # To be done
    return {
        'code': -400,
        'message': 'Authentication failed.'
    }


def auth(level='verify_token', **kw):
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
        Arg = inspect.getargspec(_hand)
        Needed = Arg.args[:-len(Arg.defaults)] if Arg.defaults else Arg.args
        Optional = dict(zip(
            Arg.args[-len(Arg.defaults if Arg.defaults else []):], Arg.defaults if Arg.defaults else []))
        HandlerArgs[_hand] = {
            'needed': Needed,
            'optional': Optional
        }

    def decorator(func):
        @wraps(func)
        def _i(*args, **kw):
            funckw = dict(request.values)

            Result = auth(level=level, as_decorator=False, **funckw)
            if Result['code'] == 0:
                return func(*args, **kw)
            else:
                return ReturnHandler(**Result, as_decorator=True)
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
            if d.accessLevel == 'public':
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
            if d.accessLevel == 'public':
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
                        if str(x.uID).lower() == str(uID).lower() and x.write == True:
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


def rolecheck(uID=None, token = None):
    if not uID or not token:
        return {
            'code':0,
            'message':'token verification failed - continue'
        }
    # Check login stat
    if uID and token:
        r = v_token(uID, token)
        if r['code']!=0:
            # Invalid login state
            return {
                'code':0,
                'message':'Not sudo - login verification failed'
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
        if u.role != 'demo' and u.role != 'temp' and u.role!='noupload':
            return {
                'code':0,
                'message':'Upload right validation succeed'
            }
    return {
        'code': -400,
        'message': 'You do not have the right to upload a document.'
    }    

levels = {
    # No longer allow direct download. In the future it will actually check the permission of the document.
    'document_access': [download_ua_check, rolecheck, doc_read],
    'doc_read': [rolecheck, doc_read],
    'doc_write': [rolecheck, doc_write],
    'verify_token': [v_token],
    'login': [_password],
    'verify_upload': [rolecheck, v_token, v_upload_permissions]
}

from database import User
from flask import request, jsonify
import inspect
from functools import wraps


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


def _password(uID, hash):

    # To be done

    return {
        'code': 0,
        'uid': uID,
        'message': 'success'
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
        if result['code'] != 0:
            return ReturnHandler(**result)

    return ReturnHandler(0, 'Authentication was successful.')

def authDec(level='password_only', **kw):
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
    if token=='test':
        return {
            'code':0,
            'message':'test_token'
        }
    return {
        'code':-400,
        'message':'Invalid token (testing)'
    }
    # pass

levels = {
    'document_access': [_test_allow]
    'verify_token': [_test_single_token]
}

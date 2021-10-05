from flask import jsonify
from flask import request
# import json

batch_endpoints = [
    # A list of flask endpoints that, when in that context, 
    # and if __skip_batch is set to true, then return the data
    # in dict form.
    # This is useful as the original form can then be jsonified
    # together with other data.
    '/batch'
]

_ExceptionDefinitions = {
    10000: 'Development mode',
    0: 'Success',
    -1: 'Request failed.',
    -10001: 'Argument {argument} was not supplied.',
    -10002: 'Conversion for {argument} could not be completed.',
    -20001: 'RequestMap could not map the route {route} to a valid endpoint.'
}


DEPRECATION_WARNING = {
    '0': {
        'code': 200,
        'response':{
            'alert':{
                'title':'Please upgrade your app from TestFlight',
                'message':'A critical upgrade had been released. This version of the app will soon be deprecated.'
            }
        }
    },
    'mac-1.0.0': {
        'code': 1200,
        'response':{
            'alert':{
                'title':'Please upgrade your app.',
                'message':'A critical upgrade had been released. This version of the app will soon be deprecated.\n\nThe update can be found at https://yyjlincoln.com/portfolio/documentx-ios'
            }
        }
    }
}


# Client-side exception bouncing


def _transparent_data_proxy(data):
    return data


def Res(code, message=None, __skip_batch=True, **kw):

    _jsonify = jsonify
    # Compatibility Layer - Determine whether this is a batch request.
    # If this is a batch request, do NOT jsonify the data; instead,
    # return it as its original form so it will be jsonified later.
    if __skip_batch:
        if request.path in batch_endpoints:
            _jsonify = _transparent_data_proxy

    if message:
        return _jsonify({**{
            'code': code,
            'message': message
        }, **kw})
    if code in _ExceptionDefinitions:
        message = _ExceptionDefinitions[code]
        for key in kw:
            # Plug the variables in
            message = message.replace('{'+key+'}', str(kw[key]))
        return _jsonify({**{
            'code': code,
            'message': message
        }, **kw})
    return _jsonify({**{
        'code': code,
        'message':'<This API did not return any messages.>'
    }, **kw})

def ResponseAutoDeprecationWarning(apiversion, code = 0, message = 'Success', **kw):
    if apiversion in DEPRECATION_WARNING:
        kw.update(DEPRECATION_WARNING[apiversion]['response'])
        return Res(DEPRECATION_WARNING[apiversion]['code'], message="Succeeded with warning", **kw)
    return Res(code=0, message=message, **kw)
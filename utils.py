from functools import wraps
import inspect
from flask import request, jsonify

def GetArgs(callback=None):
    def _w(func):
        # Pre-execution check
        # Check if callback is callable
        Arg = inspect.getargspec(func)
        Needed = Arg.args[:-len(Arg.defaults)] if Arg.defaults else Arg.args
        Optional = dict(zip(Arg.args[-len(Arg.defaults if Arg.defaults else []):],Arg.defaults if Arg.defaults else []))
        # print(Needed,Optional)
        @wraps(func)
        def _Wrap(*args,**kw):
            callargs = {}
            for x in Needed:
                v = request.values.get(x)
                if not v:
                    if callable(callback):
                        return callback(func, -1, x)
                    else:
                        return jsonify({
                            'code':-1
                        })
                callargs[x]=v
            
            for x in Optional:
                v = request.values.get(x)
                if not v:
                    callargs[x]=Optional[x]
                else:
                    callargs[x]=v
            
            kw.update(callargs)
            return func(*args,**kw)
        return _Wrap
    return _w
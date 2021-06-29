from functools import wraps
import warnings
from utils.AutoArguments import Arg
from flask import request
import inspect
from utils.ResponseModule import Res


class RequestMap():
    '''
    Use register_request() as a decorator to register a request.
    The callback (handler) function may have __channel and __fetch_values as its keyword arguments.
        __channel: string, indicating where the request came from. For example, 'flask'.
        __fetch_values: function. Calling this function with a key will retrieve the corresponding value of the key.
                        If the key does not exist, it will return None.
    However, this is optional as this program will detects whether there is a **kwargs or whether above parameters is defined
    in the callback function. If not, the values will not be passed.
    '''

    def __init__(self, always_pass_channel_and_fetch_values=False):
        self.request_map = {}
        self.pass_params = always_pass_channel_and_fetch_values

    def flask_proxy(self, func, channel, fetch_values):
        # This proxy adds any decorator and changes any values before the callback gets called.
        # e.g. this adds __channel and __fetch_values, which provides a unified interface for retrieving values from the
        # incoming request.

        # Inspect the function, get arguments
        inspected = inspect.getfullargspec(func).args

        # Determine whether there is a var_kwarg
        param = inspect.signature(func).parameters
        __kw = False
        for par in param:
            if param[par].kind == inspect.Parameter.VAR_KEYWORD:
                __kw = True

        @wraps(func)
        def _proxy(*args, **kw):
            # Using above info, attach __channel and __fetch_values
            if '__channel' in inspected or __kw == True or self.pass_params:
                kw['__channel'] = channel
            if '__fetch_values' in inspected or __kw == True or self.pass_params:
                kw['__fetch_values'] = fetch_values

            return func(*args, **kw)
        return _proxy

    def endpoint_proxy(self, func, route):
        @wraps(func)
        def _endpoint_proxy(*args, **kw):
            # This is the last layer before the actual endpoint is called.
            # However, if there is any decorators below @rmap.register_request,
            # then that will be called before the endpoint.

            # This endpoint proxy will and only will be called ONCE each request
            # (or multiple times if there is a batch request)
            # This will be particularlly good for traffic analysis and rate limiting.

            # Route metadata can be obtained through:
            # self.request_map[route]

            return func(*args, **kw)
        return _endpoint_proxy

    def register_request(self, route, *args, name=None, **kw):
        'Use __channel, __fetch_values as variables in your function to determine where the request came from, and by calling __fetch_variables you may retrieve its parameters on demand.'
        def _register_request(func):
            # Added compatibility layer such that when the function is directly called, it works as if it wasn't registered.
            @wraps(func)
            def __register_request(*fargs, **fkw):
                return func(*fargs, **fkw)

            if route in self.request_map and self.request_map[route]['func'] != func:
                warnings.warn(
                    f'WARNING: Handler {self.request_map[route]["func"].__name__} is already mapped to route {route}. It is now being overwritten by {func.__name__}.')
            # The decorator has been called, so register the request.
            self.request_map[route] = {
                'args': args,
                'kw': kw,
                # 'func': func,
                'func': self.endpoint_proxy(func, route=route),
                '_func': func,
                'name': name if name != None else func.__name__
            }
            return __register_request
        return _register_request

    @staticmethod
    def flask_values_proxy(*args, **kw):
        # This proxy MUST exist, otherwise there will be a flask runtime error "Out of context".
        # This is caused by getting the value of "request.values.get" outside context (when initializing);
        # Therefore a proxy is established to mitigate this and only access the value of "request.values.get" when it is
        # within the context.
        return request.values.get(*args, **kw)

    def handle_flask(self, app):
        '__channel = flask'
        for route in self.request_map:
            try:
                if 'methods' not in self.request_map[route]['kw']:
                    self.request_map[route]['kw']['methods'] = ['GET', 'POST']
                app.add_url_rule(
                    route, self.request_map[route]['name'], self.flask_proxy(self.request_map[route]['func'], channel='flask', fetch_values=self.flask_values_proxy), *self.request_map[route]['args'], **self.request_map[route]['kw'])
            except Exception as e:
                raise RuntimeError(
                    'Can not handle flask due to flask exception.')

    def map_request(self, route):
        if route not in self.request_map:
            return None
        else:
            return self.request_map[route]['func']

    def values_proxy(self, values):
        def _values_proxy(key):
            if key in values:
                return values[key]
            return None
        return _values_proxy

    def parse_batch(self, requestArray):
        '''
        request = {
        'route':'/......',
        'data':{......}
        }
        '''
        ret = []
        try:
            for request in requestArray:
                mapped = self.map_request(request['route'])
                if mapped:
                    ret.append(mapped(__fetch_values=self.values_proxy(
                        request['data'] if 'data' in request else {}), __channel='batch'))
                else:
                    ret.append(Res(-20001, route=request['route']))
            return Res(0, batch=ret)
        except:
            return Res(-1, 'Could not complete the request due to error. Please check whether batch argument is in the right format.')

import inspect
from flask import request
from functools import wraps
from utils.ResponseModule import Res

# Construct a decorator to automatically retrieve arguments from a HTTP request


class ReturnRaw(Exception):
    'A self-constructed validator can inherent this class and return custom info'

    def __init__(self, message):
        super().__init__(self)
        self.returned = message


def FlaskRequest(key):
    return request.values.get(key)


def DontFetch(key):
    return None


def Arg(FetchValues=FlaskRequest, PassExcessArguments=False, **TypeConversionFunction):
    '''
    Automatically generate an arguments list for a specific function, 
    and fetches the corresponding values using FetchValues (defined here) or
    __fetch_values (as an argument passed to the function, higher priority).

    Then, attempt converting the arguments to the correct types defined in TypeConversionFunction.
        For example:
            @Arg(FetchValues = FlaskRequest, test_arg_name = int)
            def func(test_arg_name):
                pass

        When the function is called, it will first check if the value is in **kwargs.
        If it is not, then it will first try __fetch_values() or FetchValues().
        If that didn't give a value, then it will throw an error and respond to the request using ResponseModule.

        If the value is obtained, then it will call int({argument_value}) and try to convert it.
        Then it will call the function func(**{test_arg_name: argument_value_converted})

    PassExcessArguments:
        By enabling this option, this module will do its best with named arguments, and instead of checking what
        the function actually needs, this module will pass on all excess parameters.

        This can cause some errors. Use this option only if Arg() is used as a middle layer 
        (i.e this decorator does not directly call func().)
        This is particularly useful when there are other decorators that may take var_kw.
    '''
    # First run - check type conversion function
    for arg in TypeConversionFunction:
        if not callable(TypeConversionFunction[arg]):
            raise Exception(
                'Callback function for argument \"'+str(arg)+'\" is invalid as it is not callable.')

    def _retrieveWrap(func):
        # Also first run, but after initialization (got the function), inspect to get the argument.

        inspected = inspect.getfullargspec(func)
        # This gets the positional arguments.
        # defaults is a subset of args, and optional ones (or keywords) are always put the the last.
        # Therefore, we can map it.
        positional = inspected.args[:-len(inspected.defaults)
                                    ] if inspected.defaults else inspected.args
        keywords = dict(
            zip(inspected.args[-len(inspected.defaults):] if inspected.defaults else [], inspected.defaults if inspected.defaults else []))
        # zip the keys and values together, then convert it to a dict

        @wraps(func)  # Wrap the function so the decorator will not be identified
        def __retrieveWrap(*args, **kw):

            # Compatibility layer with RequestMapping.
            # This allows AutoArguments to detect whether this request is from RequestMapping, and if it is, then use __fetch_values instead of default FetchValues().
            if '__fetch_values' in kw:
                FetchMethod = kw['__fetch_values']
            else:
                FetchMethod = FetchValues
            # End compatibility layer.

            callDict = {}
            if PassExcessArguments:
                callDict = kw
            
            
            for arg in positional:
                # Check if val is already in kw, if it is, then use the existing value.
                if arg in kw:
                    val = kw[arg]
                else:
                    val = FetchMethod(arg)
                
                if val == None:
                    # A positional argument does not exist - bounce back with error message
                    return Res(-10001, argument=arg)
                callDict[arg] = val

            for arg in keywords:
                # Check if there is an existing kwargs value.
                if arg in kw:
                    val = kw[arg]
                else:
                    val = FetchMethod(arg)

                if val != None:
                    # If the value is supplied, use supplied.
                    callDict[arg] = val
                else:
                    # Use default values
                    callDict[arg] = keywords[arg]

            # Now, all required arguments are in callDict. Check and convert them
            for arg in callDict:
                if arg in TypeConversionFunction:
                    try:
                        # Attempt to convert it
                        callDict[arg] = TypeConversionFunction[arg](
                            callDict[arg])
                    except ReturnRaw as e:
                        return e.returned
                    except:
                        return Res(-10002, argument=arg)
            
            return func(*args, **callDict)
        return __retrieveWrap
    return _retrieveWrap

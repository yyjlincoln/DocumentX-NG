from utils.AutoArguments import ReturnRaw
from utils.ResponseModule import Res


def StringBool(input: str) -> bool:
    if input.lower() == 'true':
        return True
    return False
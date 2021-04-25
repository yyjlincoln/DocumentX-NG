import core.userlib
import core.postlib
from utils.AutoArguments import ReturnRaw
from utils.ResponseModule import Res


def validate_user_existance(uuid):
    'The provided uuid must be associated with an existing user. If it is, return the uuid; otherwise, raise an exception.'
    if uuid:
        if core.userlib.get_user_info_by_uuid(uuid):
            return uuid
        raise ReturnRaw(Res(-105, uuid=uuid, email=uuid))


def validate_post_existance(postid):
    post = core.postlib.get_post_by_postid(postid)
    if not post:
        raise ReturnRaw(Res(-118, postid=postid))
    return postid

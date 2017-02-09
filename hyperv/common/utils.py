import requests
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

def retry_on_http_error(code, tries=5):
    def deco_retry(f):
        def f_retry(*args, **kwargs):
            mtries = tries
            if mtries <= 1:
                return f(*args, **kwargs)
            while mtries-1 > 0:
                try:
                    return f(*args, **kwargs)
                except requests.exceptions.HTTPError as err:
                    if err.response.status_code == code:
                        LOG.debug("Caught error code %(code)s. Retrying" % {
                            'code': code})
                        mtries -= 1
                    else:
                        raise err
            return f(*args, **kwargs)
        return f_retry
    return deco_retry

def diff_dictionary_keys(first, second):
    first_set = set(first.keys())
    second_set = set(second.keys())

    remove = list(first_set - second_set)
    add = list(second_set - first_set)
    sync = list(second_set & first_set)

    return (add, remove, sync)
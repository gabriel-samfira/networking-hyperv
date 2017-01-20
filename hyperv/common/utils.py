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

from django.http import HttpResponseBadRequest, HttpResponseForbidden, \
    HttpResponseNotAllowed
from django.utils.datastructures import MergeDict

from web_auth_helper import decode, DecodeException

def web_api(request_parameter_name, secret_key, permitted_methods=['POST']):
    """A Django decorator to simplify the use of the protected API on views.
    Parameters:
        request_parameter_name: The name of the actual request parameter
            containing the original data content.
        secret_key: The secret key used to decrypt the data specified in the
            request_parameter_name.
        permitted_methods: List of request method names to support on this
            URL.
    """
    def decorate(fn):
        def _check(*args, **kwargs):
            request = args[0]
            if request.method in permitted_methods:
                if not request.REQUEST.has_key(request_parameter_name):
                    return HttpResponseBadRequest('Required parameters not provided.')
                else:
                    try:
                        request_params = decode( \
                             request.REQUEST[request_parameter_name], secret_key
                        )
                    except DecodeException:
                        return HttpResponseForbidden('Your request is not allowed.')
                    _update_request_data(request, request_params)
                    return fn(*args, **kwargs)
            else:
                return HttpResponseNotAllowed(permitted_methods)
        return _check
    return decorate

def _update_request_data(request, request_params):
    """Updates the request.REQUEST dictionary, and request.POST or request.GET
    dictionary as appropriate.
    """
    # Make a copy of the request specific dictionary.
    if request.method == 'POST':
        request_dict = request.POST.copy()
    else:
        request_dict = request.GET.copy()
        
    # Update the request specific dictionary.        
    request_dict.update(request_params)
    if request.method == "POST":
        request.POST = request_dict
    else:
        request.GET = request_dict
        
#    # Update the request.REQUEST dictionary.
    post_dict = request.POST
    get_dict = request.GET
    request.REQUEST.dicts = (post_dict, get_dict)

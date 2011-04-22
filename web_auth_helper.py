import base64
import hmac
import pickle

class DecodeException(Exception):
    def __init__(self, value="Decode failed."):
        self.value = value

    def __str__(self):
        return repr(self.value)

def encode(object_to_encode, key):
    """Returns a concatenated string of: HMAC MD5 signature, a period (.),
    and a base64encoded serialized dump of a python object.
    Parameters:
        object_to_encode: A serializable python object.
        key: A secret key string.
    """
    serialized_obj_str = pickle.dumps(object_to_encode)
    hmac_obj = hmac.new(key, msg=serialized_obj_str)
    signed_request = hmac_obj.digest() + '.' + base64.b64encode(serialized_obj_str)
    return signed_request

def decode(signed_request, key):
    """Accepts a string representing a signed request, and a secret key which
    needs to be used to unpack the actual python object.
    Returns:
        On success: The actual deserialized python object.
        On failure: Raises a DecodeException.
    """
    # Split the signature and the data.
    try:
        sig, payload = signed_request.split('.', 1)
    except ValueError:
        raise DecodeException()
    
    # Decode the data back as serialized object.
    try:
        decoded_obj_str = base64.b64decode(payload)
    except TypeError:
        raise DecodeException()
    
    # Get the signature generated using the serialized object and
    # the key.
    expected_sig = hmac.new(key, msg=decoded_obj_str).digest()
    
    # If both the signatures matches.
    if sig == expected_sig:
        try:
            return pickle.loads(decoded_obj_str)
        except:
            raise DecodeException()
    # The signatures doesn't match.
    else:
        raise DecodeException()

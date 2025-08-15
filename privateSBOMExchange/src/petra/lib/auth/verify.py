from google.oauth2 import id_token
from google.auth.transport import requests

def verify_id_token(token):
    try:
        #verify the token and raise if invalid
        idinfo = id_token.verify_oauth2_token(token, requests.Request())
        return idinfo
    except ValueError as e:
        raise RuntimeError(f"Invalid ID token: {e}")

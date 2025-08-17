import os
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from requests_oauthlib import OAuth2Session
from urllib.parse import urlparse
from dotenv import load_dotenv
from urllib.parse import parse_qs, urlparse

AUTHORIZATION_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
SCOPE = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]
#The registered redirect URI for the OAuth 2.0 client
REDIRECT_URI = "http://127.0.0.1:7000/"
USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

class OAuth2CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.auth_code_url = self.path
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"You can close this window now.")

def get_authorization_response_from_local_server(expected_state):
    host, port = urlparse(REDIRECT_URI).hostname, urlparse(REDIRECT_URI).port
    httpd = HTTPServer((host, port), OAuth2CallbackHandler)
    print(f"Listening on {REDIRECT_URI} ... waiting for redirect")
    httpd.handle_request()
    query = urlparse(httpd.auth_code_url).query
    if parse_qs(query).get("state", [None])[0] != expected_state:
        raise ValueError("State mismatch: possible CSRF detected.")
    return f"{REDIRECT_URI.rstrip('/')}{httpd.auth_code_url}"

def authenticate_and_get_id_token():
    load_dotenv()
    client_id = os.environ["GOOGLE_CLIENT_ID"] 
    client_secret = os.environ["GOOGLE_CLIENT_SECRET"]

    if not client_id or not client_secret:
        raise EnvironmentError("Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variables.")
    
    # disable OAuthlib's HTTPs verification since our redirect URI is localhost
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # set the authorization parameters
    oauth = OAuth2Session(client_id, scope=SCOPE, redirect_uri=REDIRECT_URI)
    auth_url, state = oauth.authorization_url(
        AUTHORIZATION_BASE_URL,
        access_type="offline",
        prompt="select_account"
    )

    # Redirect user to Google's OAuth 2.0 server
    print("Opening browser for authentication...")
    webbrowser.open(auth_url)

    # Handle the OAuth 2.0 server response
    redirect_response = get_authorization_response_from_local_server(state)

    # Exchange the authorization code for id token
    token = oauth.fetch_token(
        TOKEN_URL,
        client_secret=client_secret,
        authorization_response=redirect_response
    )

    return token.get("id_token")

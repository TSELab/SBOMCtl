import os
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

AUTHORIZATION_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
SCOPE = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email"
]
REDIRECT_URI = "http://127.0.0.1:7000/"
USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

class OAuth2CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.auth_code_url = self.path
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"You can close this window now.")

def get_authorization_response_from_local_server(port=7000):
    httpd = HTTPServer(('127.0.0.1', port), OAuth2CallbackHandler)
    print(f"Listening on http://127.0.0.1:{port}/ ... waiting for redirect")
    httpd.handle_request()
    return f"http://127.0.0.1:{port}{httpd.auth_code_url}"

def authenticate_and_get_id_token():
    load_dotenv()
    client_id = os.environ["GOOGLE_CLIENT_ID"] 
    client_secret = os.environ["GOOGLE_CLIENT_SECRET"]

    if not client_id or not client_secret:
        raise EnvironmentError("Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variables.")

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    oauth = OAuth2Session(client_id, scope=SCOPE, redirect_uri=REDIRECT_URI)

    auth_url, state = oauth.authorization_url(
        AUTHORIZATION_BASE_URL,
        access_type="offline",
        prompt="select_account"
    )

    print("Opening browser for authentication...")
    webbrowser.open(auth_url)

    redirect_response = get_authorization_response_from_local_server()

    token = oauth.fetch_token(
        TOKEN_URL,
        client_secret=client_secret,
        authorization_response=redirect_response
    )

    return token.get("id_token")

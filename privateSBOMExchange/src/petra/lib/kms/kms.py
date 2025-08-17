from flask import Flask, jsonify
from petra.lib.auth.google_oidc import authenticate_and_get_id_token
from petra.lib.auth.verify import verify_id_token
from petra.lib.util.config import Config
from urllib.parse import urlparse
import time
import cpabe

app = Flask(__name__)

KEY_LIFETIME_HOURS = 24 * 7
current_expiry_time = int(time.time()) + KEY_LIFETIME_HOURS * 3600

# Generate CP-ABE root keys
# TODO: store these keys securely
pk, mk = cpabe.cpabe_setup()

def get_key_expiry_time():
    global current_expiry_time
    current_time = int(time.time())
    # return current expiry or set a new one if expired
    if current_time >= current_expiry_time:
        current_expiry_time = current_time + KEY_LIFETIME_HOURS * 3600
    return current_expiry_time

def authenticate_user():
    id_token = authenticate_and_get_id_token()
    idinfo = verify_id_token(id_token)
    return idinfo

def generate_secret_key(attributes):
    attributes = attributes + [f"expiry:{get_key_expiry_time()}"]
    sk = cpabe.cpabe_keygen(pk, mk, attributes)
    return sk

def get_user_attributes(email: str, name: str) -> list[str]:
    # first, we get the attributes mapped to the user's namespace
    domain = email.split("@")[-1]
    namespace_conf = Config("./config/attribute-namespace.conf")
    attributes = namespace_conf.get_attributes_for_namespace(domain)
    if not attributes:
        return jsonify({"error": f"No attributes assigned to {email}"}), 403
    
    # second, we add the default attributes from the id token
    tk_attributes = [f"name:{name}", f"namespace:{domain}"]
    attributes.extend(tk_attributes)
    return attributes

@app.route("/public-key", methods=["GET"])
def get_public_key():
    return jsonify(pk), 200

@app.route("/onboard", methods=["POST"])
def onboard():
    idinfo = authenticate_user()
    required_claims = ["email", "name"]
    missing = [c for c in required_claims if not idinfo.get(c)]
    if missing:
        return jsonify({"missing_claims": f"Missing: {', '.join(missing)}. Request correct OIDC scopes."}), 401

    email, name = idinfo["email"], idinfo["name"]
    attributes = get_user_attributes(email, name)
    if not attributes:
        return jsonify({"error": f"No attributes assigned to {email}"}), 403

    sk = generate_secret_key(attributes)

    return jsonify({
        "email": email,
        "attributes": attributes,
        "secret_key": sk
    }), 200

kms_conf = Config("./config/kms.conf")
kms_service_url = kms_conf.get_kms_service_url()

if __name__ == "__main__":
    parsed_url = urlparse(kms_service_url)
    host = parsed_url.hostname
    port = parsed_url.port

    app.run(debug=True, host=host, port=port)

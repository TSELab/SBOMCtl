# kms/kms_service.py

from flask import Flask, jsonify
from petra.lib.auth.oidc import authenticate_and_get_id_token
from petra.lib.auth.verify_oidc import verify_id_token
from petra.lib.util.config import Config
from urllib.parse import urlparse
import cpabe

app = Flask(__name__)

def cpabe_setup():
    return cpabe.cpabe_setup()

pk, mk = cpabe_setup()

def authenticate_user():
    id_token = authenticate_and_get_id_token()
    idinfo = verify_id_token(id_token)
    if not idinfo:
        return None
    return idinfo.get("email")

def onboard_user(email, pk, mk, attributes):
    if not attributes:
        return None, None, None
    sk = cpabe.cpabe_keygen(pk, mk, attributes)
    return email, attributes, sk

def get_user_attributes(email: str) -> list[str]:
    domain = email.split("@")[-1]
    namespace_conf = Config("./config/attribute-group-namespace.conf")
    
    namespace = namespace_conf.get_namespace_for_domain(domain)
    if not namespace:
        return []
    conf = Config(f"./config/{namespace}-policy.conf")
    return conf.get_cpabe_group(f"{namespace}-group")

@app.route("/")
def health():
    return jsonify({"status": "KMS is running"}), 200

@app.route("/public-key", methods=["GET"])
def get_public_key():
    return jsonify(pk), 200

@app.route("/onboard", methods=["POST"])
def onboard():
    email = authenticate_user()
    if not email:
        return jsonify({"error": "Authentication failed"}), 401

    attributes = get_user_attributes(email)
    if not attributes:
        return jsonify({"error": f"No attributes assigned to {email}"}), 403

    _, _, sk = onboard_user(email, pk, mk, attributes)

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

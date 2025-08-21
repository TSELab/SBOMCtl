

import time
import json
import jwt
import base64
import requests
from flask import Flask, jsonify
from petra.lib.auth.google_oidc import authenticate_and_get_id_token
from petra.lib.util.config import Config
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import cpabe

class KeyManagementService:
    """Key Management Service that provisions the cpabe keys and manages signing keys."""
    def __init__(self, kms_conf, key_lifetime_hours=24*356):
        self.kms_conf = kms_conf
        self.KEY_LIFETIME_HOURS = key_lifetime_hours
        self.current_expiry_time = int(time.time()) + self.KEY_LIFETIME_HOURS * 3600
        # Generate CP-ABE root keys
        # TODO: store these keys securely and load them from the secure location
        self.pk, self.mk = cpabe.cpabe_setup()

    def get_key_expiry_time(self) -> int:
        current_time = int(time.time())
        if current_time >= self.current_expiry_time:
            self.current_expiry_time = current_time + self.KEY_LIFETIME_HOURS * 3600
        return self.current_expiry_time

    def generate_secret_key(self, attributes):
        attributes = attributes + [f"expiry:{self.get_key_expiry_time()}"]
        return cpabe.cpabe_keygen(self.pk, self.mk, attributes)

    def get_user_attributes(self, email: str, name: str) -> list[str]:
        domain = email.split("@")[-1]
        attributes = self.kms_conf.get_attributes_for_namespace(domain)

        if not attributes:
            return None

        tk_attributes = [f"name:{name}", f"namespace:{domain}"]
        attributes.extend(tk_attributes)
        return attributes
    
    def authenticate_user(self, ambient=False):
        """Fetches current valid sigstore conformance token or direct the user to log in """
        if ambient:
            url = "https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/current-token/oidc-token.txt"
            response = requests.get(url)
            token = response.text.strip()
            idinfo = jwt.decode(token, options={"verify_signature": False})
            identity, name = idinfo['job_workflow_ref'], idinfo['actor_id']
        else:
            token = authenticate_and_get_id_token()
            idinfo = jwt.decode(token, options={"verify_signature": False})
            identity, name = idinfo['email'], idinfo['name']
        return token, identity, name


    def get_fulcio_cert(self, id_token, email, priv_key):
        # Generate CSR
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.EMAIL_ADDRESS, email) ]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),critical=True,))
        
        cert_request = builder.sign(priv_key, hashes.SHA256())
        
        url = "https://fulcio.sigstage.dev/api/v2/signingCert"
        headers = {
            "Authorization": f"Bearer {id_token}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        # Serialize the CSR to PEM format
        data = json.dumps({
                "certificateSigningRequest": 
                    base64.b64encode(cert_request.public_bytes(serialization.Encoding.PEM)).decode()
            })
        resp = requests.post(url=url, data=data, headers=headers)
        resp.raise_for_status()
        try:
            certificates = resp.json()["signedCertificateEmbeddedSct"]["chain"]["certificates"]
        except KeyError:
            raise Exception("Fulcio response missing certificate chain")

        if len(certificates) < 2:
            raise Exception(
                f"Certificate chain is too short: {len(certificates)} < 2"
            )
        cert = x509.load_pem_x509_certificate(certificates[0].encode())
        return cert.public_bytes(serialization.Encoding.PEM).decode()

app = Flask(__name__)
kms_conf = Config("./config/kms_and_attribute-namespace.conf")
kms_service_url = kms_conf.get_kms_service_url()
kms = KeyManagementService(kms_conf)

@app.route("/enroll", methods=["POST"])
def enroll():
    _, identity, name = kms.authenticate_user(ambient=True)
    attributes = kms.get_user_attributes(identity, name)
    if not attributes:
        return jsonify({"error": f"No attributes assigned to {identity}"}), 403

    sk = kms.generate_secret_key(attributes)

    return jsonify({
        "secret_key": sk
    }), 200

@app.route("/provision-key", methods=["POST"])
def provision_key():
    id_token, identity, _ = kms.authenticate_user(ambient=True)
    # Generate ephemeral key
    priv_key = ec.generate_private_key(ec.SECP256R1())

    # Export private key as PEM string
    priv_key_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Get Fulcio cert
    cert = kms.get_fulcio_cert(id_token, identity, priv_key)

    return jsonify({
        "cpabe_pk": kms.pk,
        "signing_key": priv_key_pem, 
        "cert": cert
    }), 200

if __name__ == "__main__":
    parsed_url = urlparse(kms_service_url)
    host = parsed_url.hostname
    port = parsed_url.port
    app.run(debug=True, host=host, port=port)

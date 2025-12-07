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
    """Handles cryptographic key management for CP-ABE and signing operations.
    - Provisions CP-ABE public/master keys.
    - Generates user secret keys with access and key expiry attributes.
    - Authenticates users via OIDC tokens (ambient/interactive).
    - Retrieves user attributes based on identity namespace.
    - Requests signing certificates from Fulcio. """
    def __init__(self, kms_conf, key_lifetime_seconds=24*30*3600):
        self.kms_conf = kms_conf
        self.KEY_LIFETIME_SECONDS = key_lifetime_seconds
        self.epoch_period_sec = key_lifetime_seconds 
        self.epoch_anchor_ts: int | None = None  
        self.pk, self.mk = cpabe.cpabe_setup()
        
    def ensure_epoch_from_token(self, id_token: str):
        """Set the epoch anchor from the token's issuedAt  once"""
        if self.epoch_anchor_ts is not None:
            return
        claims = jwt.decode(id_token, options={"verify_signature": False})
        issued_at_ts = int(claims.get("iat", int(time.time())))
        # floor to the period boundary
        self.epoch_anchor_ts = (issued_at_ts // self.epoch_period_sec) * self.epoch_period_sec
        
    def epoch_info(self) -> dict:
        """
        Compute metadata about the current epoch window relative to the fixed anchor.

        An epoch is defined by an anchor timestamp and a fixed period length
        (`self.epoch_period_sec`). Given the current wall-clock time, this method
        calculates which epoch we are in, and returns its boundaries.

        Returns:
            dict with the following keys:
                - "epoch": (int) the current epoch number (0-based).
                - "epoch_start_time_stamp": (int) UNIX timestamp (UTC) for the
                beginning of the current epoch.
                - "epoch_end_time_stamp": (int) UNIX timestamp (UTC) for the
                end of the current epoch (exclusive upper bound).
                - "epoch_period_seconds": (int) the configured length of an epoch
                in hours (from KEY_LIFETIME_SECONDS).
                - "anchor_time_stamp": (int) the fixed UNIX timestamp (UTC)
                that marks the beginning of epoch 0.

        Raises:
            RuntimeError: if `self.epoch_anchor_ts` has not been initialized yet.
        """
        if self.epoch_anchor_ts is None:
            raise RuntimeError("Epoch anchor not initialized")
        now_ts = int(time.time())
        anchor = self.epoch_anchor_ts
        if now_ts < anchor:
            epoch = 0
            epoch_start_time_stamp = anchor
        else:
            epoch = (now_ts - anchor) // self.epoch_period_sec
            epoch_start_time_stamp = anchor + epoch * self.epoch_period_sec
        epoch_end_time_stamp = epoch_start_time_stamp + self.epoch_period_sec
        return {
            "epoch": int(epoch),
            "epoch_start_time_stamp": int(epoch_start_time_stamp),
            "epoch_end_time_stamp": int(epoch_end_time_stamp),
            "epoch_period_seconds": self.KEY_LIFETIME_SECONDS,
            "anchor_time_stamp": int(anchor),
        }
        
    def generate_secret_key(self, attributes:list[str]):
        # add the end of the current epoch to attributes
        attributes = attributes + [f"epoch:{self.epoch_info()['epoch_end_time_stamp']}"] 
        print(f"\n\nattributes {attributes}")
        sk = cpabe.cpabe_keygen(self.pk, self.mk, attributes)
        return sk

    def get_user_attributes(self, email: str, name: str) -> list[str]:
        domain = email.split("@")[-1]
        attributes = self.kms_conf.get_attributes_for_namespace(domain)
        if not attributes:
            return None
        attributes.extend([f"name:{name}", f"namespace:{domain}"])
        return attributes

    def authenticate_user(self, ambient = False):
        if ambient:
            url = "https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/current-token/oidc-token.txt"
            token = requests.get(url).text.strip()
            idinfo = jwt.decode(token, options={"verify_signature": False})
            identity, name = idinfo['job_workflow_ref'], idinfo['actor_id']
        else:
            token = authenticate_and_get_id_token()
            idinfo = jwt.decode(token, options={"verify_signature": False})
            identity, name = idinfo['email'], idinfo['name']
        return token, identity, name

    def get_fulcio_cert(self, id_token, email, priv_key):
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        csr = builder.sign(priv_key, hashes.SHA256())
        url = "https://fulcio.sigstage.dev/api/v2/signingCert"
        headers = {
            "Authorization": f"Bearer {id_token}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        data = json.dumps({
            "certificateSigningRequest": base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode()
        })
        resp = requests.post(url, data=data, headers=headers)
        resp.raise_for_status()
        try:
            certs = resp.json()["signedCertificateEmbeddedSct"]["chain"]["certificates"]
        except KeyError:
            raise Exception("Fulcio response missing certificate chain")
        if len(certs) < 2:
            raise Exception(f"Certificate chain too short: {len(certs)} < 2")
        cert = x509.load_pem_x509_certificate(certs[0].encode())
        return cert.public_bytes(serialization.Encoding.PEM).decode()

def generate_ephemeral_key_and_cert(kms, id_token, identity):
    """Helper to generate ephemeral signing key and Fulcio cert"""
    priv_key = ec.generate_private_key(ec.SECP256R1())
    priv_key_pem = priv_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    ).decode("utf-8")
    cert = kms.get_fulcio_cert(id_token, identity, priv_key)
    return priv_key_pem, cert

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
        "cpabe_pk": sk,
        "expires":kms.epoch_info().get("epoch_end_time_stamp") # add key expiry time
    }), 200

@app.route("/provision-generator-keys", methods=["POST"])
def provision_generator_keys():
    id_token, identity, _ = kms.authenticate_user(ambient=True)
    priv_key_pem, cert = generate_ephemeral_key_and_cert(kms, id_token, identity)
    return jsonify({
        "cpabe_pk": kms.pk,
        "signing_key": priv_key_pem, 
        "cert": cert
    }), 200

@app.route("/provision-producer-keys", methods=["POST"])
def provision_producer_keys():
    id_token, identity, name = kms.authenticate_user(ambient=True)
    kms.ensure_epoch_from_token(id_token) # extract issuedAt (iat) from the OIDC token to use as the start time of epoch 0
    print(f"producer epoch info {kms.epoch_info()}")
    attributes = kms.get_user_attributes(identity, name)
    if not attributes:
        return jsonify({"error": f"No attributes assigned to {identity}"}), 403
    sk = kms.generate_secret_key(attributes)
    priv_key_pem, cert = generate_ephemeral_key_and_cert(kms, id_token, identity)

    return jsonify({
        "cpabe_sk": sk,
        "signing_key": priv_key_pem, 
        "cert": cert,
        "epoch_info": kms.epoch_info()
    }), 200

if __name__ == "__main__":
    parsed_url = urlparse(kms_service_url)
    host = parsed_url.hostname
    port = parsed_url.port
    app.run(debug=True, host=host, port=port)

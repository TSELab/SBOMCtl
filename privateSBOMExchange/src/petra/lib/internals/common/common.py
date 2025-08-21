import requests
import os
import tempfile
from petra.lib.util.config import Config
from cryptography.hazmat.primitives import serialization

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

def sign_sbom_tree(signing_key, sbom_tree):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(signing_key.encode("utf-8"))
        priv_key_file = f.name
    try:
        sbom_tree.sign(priv_key_file)
    finally:
        # Delete the key after signing
        os.remove(priv_key_file)
    
    return sbom_tree

def verify_sbom_tree_signature(signing_cert, sbom_tree):
    """Verifies the signature of the SBOM tree."""
    if not signing_cert or not sbom_tree:
        raise Exception("Signing cert or SBOM tree not available")

    # write the public key to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(
            signing_cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        pub_key_file = f.name
    try:
        ok = sbom_tree.verify_signature(pub_key_file)
    finally:
        os.remove(pub_key_file)
    return ok
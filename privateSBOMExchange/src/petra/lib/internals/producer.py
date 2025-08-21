import copy
import requests
import os
from petra.lib.models import DecryptVisitor
from petra.lib.util.config import Config
from petra.lib.internals.generator import Generator
from cryptography import x509
import tempfile
from cryptography.hazmat.primitives import serialization

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Producer:
    def __init__(self, artifact, policy):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = artifact
        self.policy = policy
        self.plaintext_sbom_tree = None
        self.redacted_sbom_tree = None
        self.cpabe_sk = ""
        self.decrypted_sbom_tree = None
        self.signing_cert = None

    def redact_sbom(self):
        # call generator to redact the SBOM
        generator = Generator(self.sw_artifact, self.policy)
        self.plaintext_sbom_tree, self.redacted_sbom_tree, signing_cert = generator.redact_sbom()
        self.signing_cert = x509.load_pem_x509_certificate(signing_cert.encode())

        # return the outcome of the redaction verification
        return self.verify_redaction()
    
    def decrypt_key_enroll(self):
        response = requests.post(f"{self.kms_url}/enroll")
        if response.status_code != 200:
            raise Exception(f"Failed to get secret key: {response.text}")
        self.cpabe_sk = response.json().get("secret_key")

    def decrypt_sbom(self):
        decrypt_visitor = DecryptVisitor(self.cpabe_sk)
        self.decrypted_sbom_tree = copy.deepcopy(self.redacted_sbom_tree)
        self.decrypted_sbom_tree.accept(decrypt_visitor)
    
    def verify_signature(self):
        """Verifies the signature of the redacted SBOM tree."""
        if not self.signing_cert or not self.decrypted_sbom_tree:
            raise Exception("Signing cert or decrypted tree not available for signature verification")

        # write the public key to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(
                self.signing_cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            pub_key_file = f.name
        try:
            ok = self.decrypted_sbom_tree.verify_signature(pub_key_file)
        finally:
            os.remove(pub_key_file)
        return ok

    def verify_redaction(self):
        self.decrypt_key_enroll()
        self.decrypt_sbom()
        return self.verify_signature()
    
    def get_redacted_sbom_tree(self):
        """Returns the decrypted SBOM tree."""
        # this should be provided by the distributor, for now, we get it here
        if not self.redacted_sbom_tree:
            raise Exception("Redacted SBOM tree is not available")
        return self.redacted_sbom_tree

        

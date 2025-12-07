import copy
import requests
from petra.lib.models import DecryptVisitor
from petra.lib.util.config import Config
from petra.lib.internals.generator import Generator
from cryptography import x509
from petra.lib.internals.common.common import sign_sbom_tree, verify_sbom_tree_signature

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Producer:
    def __init__(self, artifact, policy):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = artifact
        self.policy = policy
        self.plaintext_sbom_tree = None
        self.redacted_sbom_tree = None
        self.signed_redacted_sbom_tree = None
        self.decrypted_sbom_tree = None
        self.cpabe_sk = ""
        self.generator_cert = ""
        self.signing_cert = ""
        self.epoch_info = {}

    def request_redaction(self):
        # get producer keys(cpabe_sk, counter signing_key, cert)
        self.get_producer_keys()
        # call generator to redact the SBOM, send the epoch info returned by the kms
        generator = Generator(self.sw_artifact, self.policy,self.epoch_info)
        self.plaintext_sbom_tree, self.redacted_sbom_tree, signing_cert = generator.redact_sbom()
        self.generator_cert = x509.load_pem_x509_certificate(signing_cert.encode())

        # verify generator signature on redacted SBOM
        self.decrypt_sbom()
        if not verify_sbom_tree_signature(self.generator_cert, self.decrypted_sbom_tree):
            raise Exception("Generator Signature verification failed")

        # countersign the redacted SBOM
        self.signed_redacted_sbom_tree = sign_sbom_tree(self.signing_key, self.redacted_sbom_tree)

    def get_producer_keys(self):
        resp = requests.post(f"{self.kms_url}/provision-producer-keys")
        if resp.status_code != 200:
            raise Exception(f"Failed to provision key: {resp.text}")
        cpabe_sk, signing_key, cert,epoch_info = resp.json().get("cpabe_sk"), resp.json().get("signing_key"), resp.json().get("cert"),resp.json().get("epoch_info")
        if not all([cpabe_sk, signing_key, cert,epoch_info]):
            raise Exception("Failed to get cpabe_sk, signing key, certificate or epoch info from KMS")
        self.cpabe_sk, self.signing_key, self.signing_cert,self.epoch_info = cpabe_sk, signing_key, cert,epoch_info

    def decrypt_sbom(self):
        decrypt_visitor = DecryptVisitor(self.cpabe_sk)
        self.decrypted_sbom_tree = copy.deepcopy(self.redacted_sbom_tree)
        self.decrypted_sbom_tree.accept(decrypt_visitor)

    def to_distributor(self):
        """Returns the decrypted SBOM tree."""
        # producer should send this to the distributor, for now, distributor gets it from here
        if not self.signed_redacted_sbom_tree or not self.signing_cert:
            raise Exception("Signed redacted SBOM tree or producer cert is not available")
        return self.signed_redacted_sbom_tree, self.signing_cert

        

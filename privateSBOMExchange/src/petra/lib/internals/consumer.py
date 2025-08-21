import copy
import requests
from petra.lib.models import DecryptVisitor
from petra.lib.util.config import Config

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Consumer:
    def __init__(self, sw_artifact, redacted_sbom_tree):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = sw_artifact
        self.redacted_sbom_tree = redacted_sbom_tree
        self.cpabe_sk = self.enroll_decryption_key()
        self.decrypted_sbom_tree = None

    def enroll_decryption_key(self):
        response = requests.post(f"{self.kms_url}/enroll")
        if response.status_code != 200:
            raise Exception(f"Failed to get cpabe secret key: {response.text}")
        return response.json().get("cpabe_pk")

    def decrypt_sbom(self):
        decrypt_visitor = DecryptVisitor(self.cpabe_sk)
        self.decrypted_sbom_tree = copy.deepcopy(self.redacted_sbom_tree)
        self.decrypted_sbom_tree.accept(decrypt_visitor)


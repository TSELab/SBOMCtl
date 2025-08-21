import copy
import requests
from petra.lib.models import DecryptVisitor
from petra.lib.util.config import Config

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Consumer:
    def __init__(self, sw_artficat, redacted_sbom_tree):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artficat = sw_artficat
        self.redacted_sbom_tree = redacted_sbom_tree
        self.cpabe_sk = ""
        self.decrypted_tree = None
    
    def decrypt_key_enroll(self):
        response = requests.post(f"{kms_conf.get_kms_service_url()}/enroll")
        if response.status_code != 200:
            raise Exception(f"Failed to get secret key: {response.text}")
        self.cpabe_sk = response.json().get("secret_key")

    def decrypt_sbom(self):
        self.decrypt_key_enroll()
        decrypt_visitor = DecryptVisitor(self.cpabe_sk)
        self.decrypted_sbom_tree = copy.deepcopy(self.redacted_sbom_tree)
        self.decrypted_sbom_tree.accept(decrypt_visitor)


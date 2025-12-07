import copy
import time
import requests
from petra.models import DecryptVisitor
from petra.util.config import Config

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Consumer:
    def __init__(self, sw_artifact, redacted_sbom_tree):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = sw_artifact
        self.redacted_sbom_tree = redacted_sbom_tree
        self.key_expiry:int = 0
        self.cpabe_sk = self.enroll_decryption_key()
        self.decrypted_sbom_tree = None

    def enroll_decryption_key(self):
        response = requests.post(f"{self.kms_url}/enroll")
        if response.status_code != 200:
            raise Exception(f"Failed to get cpabe secret key: {response.text}")
        self.key_expiry = response.json().get("expires")
        return response.json().get("cpabe_pk")

    def decrypt_sbom(self):
        #check if key is expired already
        now=int(time.time())
        if(now<self.key_expiry):
            decrypt_visitor = DecryptVisitor(self.cpabe_sk)
            self.decrypted_sbom_tree = copy.deepcopy(self.redacted_sbom_tree)
            self.decrypted_sbom_tree.accept(decrypt_visitor)
        else:
            print("Expired decryption key, cannot decrypt. Please re-enroll to get a new key")


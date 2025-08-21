import copy
from lib4sbom.parser import SBOMParser
import requests

from petra.lib.models.tree_ops import build_sbom_tree
from petra.lib.models import MerkleVisitor, EncryptVisitor
from petra.lib.util.config import Config
from petra.lib.internals.common.common import sign_sbom_tree

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Generator:
    def __init__(self, sw_artifact, policy):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = sw_artifact
        self.policy = policy
        self.cpabe_pk = ""
        self.signing_key = ""
        self.cert = ""  
    
    def get_generator_keys(self):
        response = requests.post(f"{self.kms_url}/provision-generator-keys")
        if response.status_code != 200:
            raise Exception(f"Failed to provision key: {response.text}")
        cpabe_pk, signing_key, cert = response.json().get("cpabe_pk"), response.json().get("signing_key"), response.json().get("cert")
        if not all([cpabe_pk, signing_key, cert]):
            raise Exception("Failed to get signing key or certificate from KMS")
        self.cpabe_pk, self.signing_key, self.cert = cpabe_pk, signing_key, cert

    def redact_sbom(self):
        # build sbom tree
        SBOM_parser = SBOMParser()   
        SBOM_parser.parse_file(self.sw_artifact)

        # build sbom tree
        sbom=SBOM_parser.sbom
        sbom_tree = build_sbom_tree(sbom, self.policy)
        plaintext_sbom_tree = copy.deepcopy(sbom_tree)

        # request keys(cpabe_pk, (counter)signing key pair and cert) from KMS
        self.get_generator_keys()

        # encrypt node data
        encrypt_visitor = EncryptVisitor(self.cpabe_pk)
        sbom_tree.accept(encrypt_visitor)

        # hash tree nodes
        merkle_visitor = MerkleVisitor()
        merkle_root_hash_original = sbom_tree.accept(merkle_visitor)

        # sign the tree
        sbom_tree = sign_sbom_tree(self.signing_key, sbom_tree)

        return plaintext_sbom_tree, sbom_tree, self.cert
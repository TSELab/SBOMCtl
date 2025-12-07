import copy
from typing import List
from lib4sbom.parser import SBOMParser
import requests

from petra.lib.models.tree_ops import build_sbom_tree
from petra.lib.models import MerkleVisitor, EncryptVisitor
from petra.lib.util.config import Config
from petra.lib.internals.common.common import sign_sbom_tree

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Generator:
    def __init__(self, sw_artifact, policy,epoch_info):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = sw_artifact
        self.policy = policy
        self.cpabe_pk = ""
        self.signing_key = ""
        self.cert = ""
        self.epoch_info:Dict = epoch_info
    
    def get_generator_keys(self):
        response = requests.post(f"{self.kms_url}/provision-generator-keys")
        if response.status_code != 200:
            raise Exception(f"Failed to provision key: {response.text}")
        cpabe_pk, signing_key, cert = response.json().get("cpabe_pk"), response.json().get("signing_key"), response.json().get("cert")
        if not all([cpabe_pk, signing_key, cert]):
            raise Exception("Failed to get signing key or certificate from KMS")
        self.cpabe_pk, self.signing_key, self.cert = cpabe_pk, signing_key, cert

    def redact_sbom(self):
        time_tree_clause: str =self.make_time_access_tree()
        
        # build sbom tree
        SBOM_parser = SBOMParser()   
        SBOM_parser.parse_file(self.sw_artifact)
        sbom = SBOM_parser.sbom
        sbom_tree = build_sbom_tree(sbom,time_tree_clause,self.policy)
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
    
    def epoch_end_list_from_info(self,count: int=12) -> List[str]:
        """
        Return a list of epoch end timestamps starting from the current epoch
        """
        period_sec = int(self.epoch_info ["epoch_period_seconds"])
        start = int(self.epoch_info["epoch_end_time_stamp"])
        return [f"\"epoch:{start + i * period_sec}\"" for i in range(count)]

    def make_time_access_tree(self) -> str:
        """_summary_
        construct time tree as string from list of epoch end timestamps 
        ABE-safe atoms for rabe-like parsers
        Returns:
            str: time tree as string
        none-tree is returned if there's no expiry list
        """
        epoch_end_list = self.epoch_end_list_from_info()
        return "(" + " or ".join(epoch_end_list) + ")" if epoch_end_list else "(epoch_end_none)"




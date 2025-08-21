import copy
from lib4sbom.parser import SBOMParser
import os
import tempfile
import json
import argparse
import requests

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config
from petra.lib.models import SbomNode
from cryptography.hazmat.primitives import serialization
from petra.lib.models.tree_ops import serialize_tree

kms_conf = Config("./config/kms_and_attribute-namespace.conf")

class Generator:
    def __init__(self, sw_artifact, policy):
        self.kms_url = kms_conf.get_kms_service_url()
        self.sw_artifact = sw_artifact
        self.policy = policy
        self.cpabe_pk = ""
        self.signing_key = ""
        self.cert = ""  
    
    def get_keys(self):
        response = requests.post(f"{self.kms_url}/provision-key")
        if response.status_code != 200:
            raise Exception(f"Failed to provision key: {response.text}")
        cpabe_pk, signing_key, cert = response.json().get("cpabe_pk"), response.json().get("signing_key"), response.json().get("cert")
        if not cpabe_pk or not signing_key or not cert:
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
        self.get_keys()

        # encrypt node data
        encrypt_visitor = EncryptVisitor(self.cpabe_pk)
        sbom_tree.accept(encrypt_visitor)

        # hash tree nodes
        merkle_visitor = MerkleVisitor()
        merkle_root_hash_original = sbom_tree.accept(merkle_visitor)

        # sign the tree
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(self.signing_key.encode("utf-8"))
            priv_key_file = f.name
        try:
            sbom_tree.sign(priv_key_file)
        finally:
            # Delete the key after signing
            os.remove(priv_key_file)

        return plaintext_sbom_tree, sbom_tree, self.cert
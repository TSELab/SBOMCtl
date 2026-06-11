import copy
import tempfile
import unittest
from lib4sbom.parser import SBOMParser
import json

from petra.models.tree_ops import build_sbom_tree, verify_sameness
from petra.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.util.config import Config

import cpabe


class TestCP_ABE_AES(unittest.TestCase):
    def test_serial_enc_dec_visitors(self):
        # read in the IP policy config
        conf = Config("./config/ip-policy.conf")

        sbom_file = conf.get_sbom_files()[0]

        pk, mk = cpabe.cpabe_setup()
        time_attributes = "epoch:1767744000"
        user_attributes = conf.get_cpabe_group("ip-group")
        user_attributes.append(time_attributes)
        sk = cpabe.cpabe_keygen(pk, mk, user_attributes)

        # Parse SPDX data into a Document object
        SBOM_parser = SBOMParser()
        SBOM_parser.parse_file(sbom_file)

        # build sbom tree
        sbom = SBOM_parser.sbom
        time_tree = '("epoch:1767744000")'

        sbom_tree = build_sbom_tree(sbom, time_tree, conf.get_cpabe_policy("ip-policy"))

        with tempfile.TemporaryFile(mode="w+") as f:
            f.write(json.dumps(sbom_tree.to_dict(), indent=4) + "\n")

        # encrypt node data
        encrypt_visitor = EncryptVisitor(pk)
        sbom_tree.accept(encrypt_visitor)

        # hash tree nodes
        merkle_visitor = MerkleVisitor()
        sbom_tree.accept(merkle_visitor)

        sbom_tree.sign(conf.get_tree_signing_key())

        # decrypt node data
        decrypt_visitor = DecryptVisitor(sk)
        decrypted_tree = copy.deepcopy(sbom_tree)
        decrypted_tree.accept(decrypt_visitor)

        with tempfile.TemporaryFile(mode="w+") as f:
            f.write(json.dumps(decrypted_tree.to_dict(), indent=4) + "\n")

        self.assertTrue(decrypted_tree.verify_signature(conf.get_tree_public_key()))

        passed = verify_sameness(sbom_tree, decrypted_tree)

        self.assertTrue(passed)

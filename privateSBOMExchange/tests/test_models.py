import configparser
import unittest
from lib4sbom.parser import SBOMParser

from petra.models import EncryptVisitor, MerkleVisitor, PrintVisitor
from petra.models.tree_ops import build_sbom_tree
from petra.util.config import Config

"""This tests inserting a sbom as tree ,assuming Non of the dependencies has its own sbom 
"""


class TestModels(unittest.TestCase):
    def test_sbom_with_child_load(self):
        # get the SBOM from the basic config
        conf = Config("config/bom-only.conf")
        bom_file = conf.get_sbom_files()[0]

        config = configparser.ConfigParser()
        config.read("config/config.ini")
        policy_file = config["POLICY"]["empty_policy"]

        # Parse SPDX data into a Document object
        SBOM_parser = SBOMParser()
        SBOM_parser.parse_file(bom_file)
        # SBOM_parser.parse_file("simple_sbom.json")
        # Build the tree and compute the root hash
        sbom = SBOM_parser.sbom
        sbom_tree = build_sbom_tree(sbom, "", policy_file)

        print_visitor = PrintVisitor()
        sbom_tree.accept(print_visitor)

        encrypt_visitor = EncryptVisitor("policy")
        sbom_tree.accept(encrypt_visitor)

        merkle_visitor = MerkleVisitor()
        merkle_root_hash = sbom_tree.accept(merkle_visitor)
        # Convert the root hash to a hexadecimal representation for display
        merkle_root_hash_hex = merkle_root_hash.hex()

        sbom_tree.accept(print_visitor)

        self.assertNotEqual(merkle_root_hash_hex, None)

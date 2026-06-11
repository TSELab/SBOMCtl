import copy
import json
import tempfile
import unittest
from lib4sbom.parser import SBOMParser

from petra.models.tree_ops import build_sbom_tree, verify_sameness
from petra.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.models import parallel_encrypt, parallel_minimal
from petra.util.config import Config
import cpabe


class TestCPABE(unittest.TestCase):
    def test_redaction_roundtrip(self):
        for encryptor, decryptor in [
            (EncryptVisitor, DecryptVisitor),
            (
                parallel_encrypt.ParallelEncryptVisitor,
                parallel_encrypt.ParallelDecryptVisitor,
            ),
            (
                parallel_minimal.ParallelEncryptVisitor,
                parallel_minimal.ParallelDecryptVisitor,
            ),
        ]:
            with self.subTest(encryptor=encryptor, decryptor=decryptor):
                conf = Config("config/ip-policy.conf")
                sbom_file = conf.get_sbom_files()[0]

                pk, mk = cpabe.cpabe_setup()
                user_attributes = conf.get_cpabe_group("ip-group")
                user_attributes.append("epoch:1767744000")
                sk = cpabe.cpabe_keygen(pk, mk, user_attributes)

                SBOM_parser = SBOMParser()
                SBOM_parser.parse_file(sbom_file)

                sbom = SBOM_parser.sbom
                time_tree = '("epoch:1767744000")'
                sbom_tree = build_sbom_tree(
                    sbom, time_tree, conf.get_cpabe_policy("ip-policy")
                )
                with tempfile.TemporaryFile(mode="w+") as f:
                    json.dump(sbom_tree.to_dict(), f)

                # encrypt node data (before hashing the tree)
                encrypt_visitor = encryptor(pk)
                sbom_tree.accept(encrypt_visitor)
                if hasattr(encrypt_visitor, "finalize"):
                    encrypt_visitor.finalize()

                # hash tree nodes
                sbom_tree.accept(MerkleVisitor())

                with tempfile.TemporaryFile(mode="w+") as f:
                    json.dump(sbom_tree.to_dict(), f)

                # decrypt a copy of the redacted tree
                redacted_tree = copy.deepcopy(sbom_tree)
                decrypt_visitor = decryptor(sk)
                redacted_tree.accept(decrypt_visitor)
                if hasattr(decrypt_visitor, "finalize"):
                    decrypt_visitor.finalize()

                with tempfile.TemporaryFile(mode="w+") as f:
                    json.dump(redacted_tree.to_dict(), f)

                # the decrypted tree must be provably the same as the redacted tree
                self.assertTrue(verify_sameness(sbom_tree, redacted_tree))

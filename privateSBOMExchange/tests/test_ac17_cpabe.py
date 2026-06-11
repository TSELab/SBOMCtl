import copy
import unittest
from lib4sbom.parser import SBOMParser
from petra.util.config import Config

from petra.models.tree_ops import verify_sameness, build_sbom_tree
from petra.models import MerkleVisitor
from petra.models import parallel_encrypt, parallel_minimal
import cpabe


class TestAC17_CPABE(unittest.TestCase):
    def test_redaction_roundtrip(self):
        for encryptor, decryptor in [
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
                bom_conf = Config("config/bom-only.conf")
                policy_conf = Config("config/ip-policy.conf")

                sbom_file = bom_conf.get_sbom_files()[0]
                ip_policy_file = policy_conf.get_cpabe_policy("ip-policy")

                ip_group = policy_conf.get_cpabe_group("ip-group")
                ip_group.append("epoch:1767744000")

                pk, mk = cpabe.ac17_cpabe_setup()
                sk = cpabe.ac17_cpabe_keygen(mk, ip_group)

                SBOM_parser = SBOMParser()
                SBOM_parser.parse_file(sbom_file)

                sbom = SBOM_parser.sbom
                time_tree = '("epoch:1767744000")'
                sbom_tree = build_sbom_tree(sbom, time_tree, ip_policy_file)

                # encrypt node data (before hashing so redaction's captured)
                # TODO: Enforce this ordering so it can't be messed up
                encrypt_visitor = encryptor(pk, "ac17")
                sbom_tree.accept(encrypt_visitor)
                encrypt_visitor.finalize()

                # hash tree nodes
                sbom_tree.accept(MerkleVisitor())

                # decrypt a copy of the redacted tree
                redacted_tree = copy.deepcopy(sbom_tree)
                decrypt_visitor = decryptor(sk, "ac17")
                redacted_tree.accept(decrypt_visitor)
                decrypt_visitor.finalize()

                # the decrypted tree must be provably the same as the redacted tree
                self.assertTrue(verify_sameness(sbom_tree, redacted_tree))

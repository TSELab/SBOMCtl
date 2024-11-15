"""This tests whether a target has is a member of a tree 
"""
import copy

from lib4sbom.parser import SBOMParser
from petra.lib.util.config import Config
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.models.tree_ops import GetTargetNodes, get_membership_proof, verify_membership_proof,build_sbom_tree
import cpabe

def is_member(root_hash, target_hash, proof):
    return verify_membership_proof(root_hash, target_hash, proof)

conf = Config("config/log4j-membership-policy.conf")
sbom_file = conf.get_sbom_files()[0]
pk, mk = cpabe.cpabe_setup()
sk = cpabe.cpabe_keygen(pk, mk, conf.get_cpabe_group('vuln-group'))

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom, conf.get_cpabe_policy('vuln-policy'),)

encrypt_visitor = EncryptVisitor(pk)
sbom_tree.accept(encrypt_visitor)
print("done encrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

# decrypt node data
decrypt_visitor = DecryptVisitor(sk)
decrypted_tree = copy.deepcopy(sbom_tree)
decrypted_tree.accept(decrypt_visitor)
print("done decrypting")

# search for a specific field node in the tree and recompute its hash
hash_hunter = GetTargetNodes(b"name:log4j-core")
decrypted_tree.accept(hash_hunter)
target_hash=hash_hunter.get_target_hash()

#Get and verify membership proof
proof = get_membership_proof(sbom_tree, target_hash)
assert is_member(merkle_root_hash, target_hash, proof) == True
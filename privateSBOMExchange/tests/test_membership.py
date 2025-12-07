"""This tests whether a target has is a member of a tree 
"""
from lib4sbom.parser import SBOMParser
from petra.util.config import Config
from petra.models import  MerkleVisitor
from petra.models.tree_ops import build_sbom_tree,GetTargetNodes, get_membership_proof, verify_membership_proof
def is_member(root_hash, target_hash, proof):
    return verify_membership_proof(root_hash, target_hash, proof)

conf = Config("config/bom-only.conf")
bom_file = conf.get_sbom_files()[0]


# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(bom_file)     
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)


# hash nodes in the tree
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)


# Retrieve hashes of all nodes in the tree
hash_hunter = GetTargetNodes()
sbom_tree.accept(hash_hunter)
target_hashes = hash_hunter.get_hashes()

#Get and verify membership proof
for hash in target_hashes:
    proof = get_membership_proof(sbom_tree, hash)
    assert is_member(merkle_root_hash, hash, proof) == True

# negative test
assert get_membership_proof(sbom_tree, [b'lol']) == None
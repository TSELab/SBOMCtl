from lib4sbom.parser import SBOMParser

from petra.lib.models import *
"""This tests inserting a sbom as tree ,assuming Non of the dependencies has its own sbom 
"""
# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file("../sbom_data/bom-shelter/in-the-wild/spdx/julia.spdx.json")   
#SBOM_parser.parse_file("simple_sbom.json")
# Build the tree and compute the root hash
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)
print_visitor = PrintVisitor()
sbom_tree.accept(print_visitor)
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)
print_visitor = PrintVisitor()
sbom_tree.accept(print_visitor)
# Convert the root hash to a hexadecimal representation for display
merkle_root_hash_hex = merkle_root_hash.hex()
print("Merkle Root Hash for SBOM:", merkle_root_hash_hex)

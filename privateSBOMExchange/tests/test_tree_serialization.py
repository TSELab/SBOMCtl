from lib4sbom.parser import SBOMParser
import json

from petra.lib.util.config import Config
from petra.lib.models import build_sbom_tree, MerkleVisitor
from petra.lib.models.tree_ops import serialize_tree

conf = Config("config/bom-only.conf")
bom_file = conf.get_sbom_files()[0]

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(bom_file)   

# build the test SBOM tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)

# hash the tree
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

print(json.dumps(serialize_tree(sbom_tree)))

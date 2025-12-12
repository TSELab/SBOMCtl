import configparser
from lib4sbom.parser import SBOMParser
import json

from petra.util.config import Config
from petra.models import  MerkleVisitor, SbomNode, PrintVisitor
from petra.models.tree_ops import serialize_tree, build_sbom_tree

conf = Config("config/bom-only.conf")
bom_file = conf.get_sbom_files()[0]

config = configparser.ConfigParser()
config.read('config/config.ini')
policy_file =  config['POLICY']['empty_policy']

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(bom_file)   

# build the test SBOM tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom,"",policy_file)

# hash the tree
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

# serialize the tree
json_tree = json.dumps(serialize_tree(sbom_tree))

print(json_tree)

# deserialize the tree
dict_tree = json.loads(json_tree)

deser_sbom_tree = SbomNode.from_dict(dict_tree)

# compare hashes here
assert merkle_root_hash.hex() == deser_sbom_tree.hash.hex()

# print the deserialized tree
print_visitor = PrintVisitor()
deser_sbom_tree.accept(print_visitor)

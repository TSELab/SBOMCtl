import copy
from lib4sbom.parser import SBOMParser
from petra.lib.util.config import Config
import json

from petra.lib.models.tree_ops import build_sbom_tree, sameness_verify
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
import cpabe

# read in the IP policy config
conf = Config("./config/tiny.conf")

sbom_file = conf.get_sbom_files()[0]

pk, mk = cpabe.cpabe_setup()
sk = cpabe.cpabe_keygen(pk, mk, conf.get_cpabe_group('name-group'))

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom, conf.get_cpabe_policy('name-policy'))

print("done constructing tree")

# encrypt node data
encrypt_visitor = EncryptVisitor(pk)
sbom_tree.accept(encrypt_visitor)
print("done encrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

print("saving encrypted tree to disk")

with open("./data/docker-tiny-redacted.json", "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

# decrypt node data
decrypt_visitor = DecryptVisitor(sk)
redacted_tree = copy.deepcopy(sbom_tree)
redacted_tree.accept(decrypt_visitor)
print("done decrypting")

with open("./data/julia-ip-decrypted.json", "w+") as f:
        f.write(json.dumps(redacted_tree.to_dict(), indent=4)+'\n')

# verify decrypted tree is consistent 
# with original sbom tree
sameness_verify(redacted_tree)

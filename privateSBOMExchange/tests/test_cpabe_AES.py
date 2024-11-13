import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.lib.models.tree_ops import build_sbom_tree
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config

import cpabe

argparser = argparse.ArgumentParser()
# TODO: add args for the config
# TODO: handle defaults etc
argparser.add_argument("-o", "--original-file", type=str, required=True, help="the file to which to write the original SBOM tree")
argparser.add_argument("-r", "--redacted-file", type=str, required=True, help="the file to which to write the redacted SBOM tree")
argparser.add_argument("-d", "--decrypted-file", type=str, required=True, help="the file to which to write the decrypted SBOM tree")
args = argparser.parse_args()

# read in the IP policy config
conf = Config("./config/test-AES.conf")

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

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

with open(args.original_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')


# encrypt node data
encrypt_visitor = EncryptVisitor(pk)
sbom_tree.accept(encrypt_visitor)
print("done encrypting")

# decrypt node data
decrypt_visitor = DecryptVisitor(sk)
decrypted_tree = copy.deepcopy(sbom_tree)
decrypted_tree.accept(decrypt_visitor)
print("done decrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

print("done hashing tree")


print("saving redacted tree to disk")

with open(args.redacted_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

# decrypt node data
decrypt_visitor = DecryptVisitor(sk)
decrypted_tree = copy.deepcopy(sbom_tree)
decrypted_tree.accept(decrypt_visitor)
print("done decrypting")


print("saving decrypted tree to disk")

with open(args.decrypted_file, "w+") as f:
        f.write(json.dumps(decrypted_tree.to_dict(), indent=4)+'\n')

# verify decrypted tree is consistent 
# with original sbom tree


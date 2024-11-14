import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config

import cpabe

argparser = argparse.ArgumentParser()
# TODO: add args for the config
# TODO: handle defaults etc
argparser.add_argument("-u", "--unredacted-file", type=str, required=True, help="the file to which to write the unredacted SBOM tree")
argparser.add_argument("-r", "--redacted-file", type=str, required=True, help="the file to which to write the redacted SBOM tree")
argparser.add_argument("-d", "--decrypted-file", type=str, required=True, help="the file to which to write the decrypted SBOM tree")
args = argparser.parse_args()

# read in the IP policy config
#conf = Config("./config/test-AES.conf")
conf = Config("./config/ip-policy.conf")

sbom_file = conf.get_sbom_files()[0]

pk, mk = cpabe.cpabe_setup()
sk = cpabe.cpabe_keygen(pk, mk, conf.get_cpabe_group('ip-group'))

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom, conf.get_cpabe_policy('ip-policy'))

print("done constructing tree")

with open(args.unredacted_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

# encrypt node data
encrypt_visitor = EncryptVisitor(pk)
sbom_tree.accept(encrypt_visitor)
print("done encrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash_original = sbom_tree.accept(merkle_visitor)

print("done hashing tree")

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
passed = verify_sameness(sbom_tree, decrypted_tree)

print("full tree sameness verification passed? %s" % str(passed))

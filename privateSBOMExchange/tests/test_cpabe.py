import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.models.tree_ops import build_sbom_tree, verify_sameness
from petra.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.models.parallel_encrypt import ParallelEncryptVisitor, ParallelDecryptVisitor
from petra.util.config import Config

import cpabe

argparser = argparse.ArgumentParser()
# TODO: add args for the config
# TODO: handle defaults etc
argparser.add_argument("-o", "--original-file", type=str, required=True, help="the file to which to write the original SBOM tree")
argparser.add_argument("-r", "--redacted-file", type=str, required=True, help="the file to which to write the redacted SBOM tree")
argparser.add_argument("-d", "--decrypted-file", type=str, required=True, help="the file to which to write the decrypted SBOM tree")
argparser.add_argument("--no-parallel", action='store_true', help="flag indicating whether to parallelize SBOM tree encryption/decryption")
args = argparser.parse_args()

# read in the IP policy config
conf = Config("./config/ip-policy.conf")

sbom_file = conf.get_sbom_files()[0]

pk, mk = cpabe.cpabe_setup()
time_attributes="epoch:1767744000"
user_attributes=conf.get_cpabe_group('ip-group')
user_attributes.append(time_attributes)
sk = cpabe.cpabe_keygen(pk, mk, user_attributes)

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
time_tree="(\"epoch:1767744000\")"
sbom_tree = build_sbom_tree(sbom,time_tree ,conf.get_cpabe_policy('ip-policy'))

print("done constructing tree")

with open(args.original_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

print("pre-redaction plaintext hash: %s" % sbom_tree.plaintext_hash.hex())

# encrypt node data
if args.no_parallel:
        encrypt_visitor = EncryptVisitor(pk)
        sbom_tree.accept(encrypt_visitor)
else:
        # we default to the parallel encryption
        encrypt_visitor = ParallelEncryptVisitor(pk)
        sbom_tree.accept(encrypt_visitor)
        encrypt_visitor.finalize()

print("done encrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

print("done hashing tree")

print("redacted plaintext hash: %s" % sbom_tree.plaintext_hash.hex())

print("saving redacted tree to disk")

with open(args.redacted_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

# decrypt node data
decrypted_tree = copy.deepcopy(sbom_tree)
if args.no_parallel:
        decrypt_visitor = DecryptVisitor(sk)
        decrypted_tree.accept(decrypt_visitor)
else:
        # we default to the parallel decryption
        decrypt_visitor = ParallelDecryptVisitor(sk)
        decrypted_tree.accept(decrypt_visitor)
        decrypt_visitor.finalize()

print("done decrypting")

print("decrypted plaintext hash: %s" % decrypted_tree.plaintext_hash.hex())

print("saving decrypted tree to disk")

with open(args.decrypted_file, "w+") as f:
        f.write(json.dumps(decrypted_tree.to_dict(), indent=4)+'\n')

# verify decrypted tree is consistent 
# with original sbom tree
passed = verify_sameness(sbom_tree, decrypted_tree)

print("full tree sameness verification passed? %s" % str(passed))

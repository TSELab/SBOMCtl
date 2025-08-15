import copy
from lib4sbom.parser import SBOMParser
import json
import argparse
import requests

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config

argparser = argparse.ArgumentParser()
# TODO: add args for the config
# TODO: handle defaults etc
argparser.add_argument("-u", "--unredacted-file", type=str, help="the file to which to write the unredacted SBOM tree")
argparser.add_argument("-r", "--redacted-file", type=str, help="the file to which to write the redacted SBOM tree")
argparser.add_argument("-d", "--decrypted-file", type=str, help="the file to which to write the decrypted SBOM tree")
args = argparser.parse_args()

# read in the IP policy config
#conf = Config("./config/test-AES.conf")
conf = Config("./config/ip-policy.conf")

sbom_file = conf.get_sbom_files()[0]

kms_conf = Config("./config/kms.conf")
kms_service_url = kms_conf.get_kms_service_url()

response = requests.get(f"{kms_service_url}/public-key")
if response.status_code != 200:
    print("Failed to get public key")
    exit(1)
pk = response.json()

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom, conf.get_cpabe_policy('ip-policy'))

print("done constructing tree")

if args.unredacted_file:
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

print("signing the tree")
sbom_tree.sign(conf.get_tree_signing_key())

# decrypt node data
response = requests.post(f"{kms_service_url}/onboard")
if response.status_code != 200:
    raise Exception(f"Failed to get secret key: {response.text}")
sk = response.json().get("secret_key")

decrypt_visitor = DecryptVisitor(sk)
decrypted_tree = copy.deepcopy(sbom_tree)
decrypted_tree.accept(decrypt_visitor)
print("done decrypting")

print("saving decrypted tree to disk")

if args.decrypted_file:
    with open(args.decrypted_file, "w+") as f:
        f.write(json.dumps(decrypted_tree.to_dict(), indent=4)+'\n')

print("decrypted tree signature verification passed? %s" % str(decrypted_tree.verify_signature(conf.get_tree_public_key())))

# verify decrypted tree is consistent 
# with original sbom tree
passed = verify_sameness(sbom_tree, decrypted_tree)

print("full tree sameness verification passed? %s" % str(passed))

import copy
from lib4sbom.parser import SBOMParser
from petra.lib.util.config import Config

from petra.lib.models.tree_ops import hash_plaintext, sameness_verify
from petra.lib.models import build_sbom_tree, MerkleVisitor, EncryptVisitor, DecryptVisitor
import cpabe

conf = Config("config/bom-only.conf")
sbom_file = conf.get_sbom_files()[0]
policy_file = conf.get_cpabe_public_key()


pk, mk = cpabe.cpabe_setup()
Groups = conf.get_cpabe_group()
sk = cpabe.cpabe_keygen(pk, mk, Groups)

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)

# hash the contents of the node
hash_plaintext(sbom_tree)


# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

for policy_file in policy_file:
    # encrypt node data
    encrypt_visitor = EncryptVisitor(pk,policy_file)
    sbom_tree.accept(encrypt_visitor)
    print("done encrypting")

    # decrypt node data
    decrypt_visitor = DecryptVisitor(sk)
    redacted_tree = copy.deepcopy(sbom_tree)
    redacted_tree.accept(decrypt_visitor)
    print("done decrypting")

    # verify decrypted tree is consistent 
    # with original sbom tree
    sameness_verify(redacted_tree)




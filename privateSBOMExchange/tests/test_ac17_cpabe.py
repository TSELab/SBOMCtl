import copy
from lib4sbom.parser import SBOMParser
from petra.util.config import Config

from petra.models.tree_ops import verify_sameness ,build_sbom_tree
from petra.models.parallel_encrypt import ParallelEncryptVisitor, ParallelDecryptVisitor
from petra.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
import cpabe

bom_conf = Config("config/bom-only.conf")
policy_conf = Config("config/ip-policy.conf")

# get all config files
sbom_file = bom_conf.get_sbom_files()[0]
ip_policy_file = policy_conf.get_cpabe_policy("ip-policy")

# get cpabe groups
ip_group = policy_conf.get_cpabe_group('ip-group')
time_attributes="epoch:1767744000"
ip_group.append(time_attributes)

pk, mk = cpabe.ac17_cpabe_setup()
sk = cpabe.ac17_cpabe_keygen(mk, ip_group)

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
time_tree="(\"epoch:1767744000\")"

sbom_tree = build_sbom_tree(sbom,time_tree,ip_policy_file)

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)


# encrypt node data
encrypt_visitor = ParallelEncryptVisitor(pk, "ac17")
sbom_tree.accept(encrypt_visitor)
encrypt_visitor.finalize()
print("done encrypting")

# decrypt node data
decrypt_visitor = ParallelDecryptVisitor(sk, "ac17")
redacted_tree = copy.deepcopy(sbom_tree)
redacted_tree.accept(decrypt_visitor)
decrypt_visitor.finalize()
print("done decrypting")

# verify decrypted tree is consistent 
# with original sbom tree
verify_sameness(sbom_tree,redacted_tree)




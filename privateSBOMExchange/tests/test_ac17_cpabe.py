import copy
from lib4sbom.parser import SBOMParser
from petra.lib.util.config import Config

from petra.lib.models.tree_ops import sameness_verify
from petra.lib.models.parallel_encrypt import ParallelEncryptVisitor, ParallelDecryptVisitor
from petra.lib.models import build_sbom_tree, MerkleVisitor, EncryptVisitor, DecryptVisitor
import cpabe

bom_conf = Config("config/bom-only.conf")
policy_conf = Config("config/policy.conf")
group_conf = Config("config/group.conf")

# get all config files
sbom_file = bom_conf.get_sbom_files()[0]
ip_policy_file = policy_conf.get_ip_policy()
weakness_policy_file = policy_conf.get_weakness_policy()

# get cpabe groups
ip_group = group_conf.get_ip_group()
weakness_group = group_conf.get_weakness_group()


pk, mk = cpabe.ac17_cpabe_setup()
sk = cpabe.ac17_cpabe_keygen(mk, ip_group)

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)


# encrypt node data
encrypt_visitor = ParallelEncryptVisitor(pk,ip_policy_file, "ac17")
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
sameness_verify(redacted_tree)




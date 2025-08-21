import copy
from lib4sbom.parser import SBOMParser
import json
import argparse
import requests

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config
from petra.lib.models import SbomNode
from petra.lib.models.tree_ops import serialize_tree
from petra.lib.internals.producer import Producer
from petra.lib.internals.consumer import Consumer


# read in the IP policy config
conf = Config("./config/ip-policy.conf")

# get the SBOM file and policy
sbom_file = conf.get_sbom_files()[0]
policy_file = conf.get_cpabe_policy('ip-policy')

# instantiate the producer and redact the SBOM
producer = Producer(sbom_file, policy_file)
ok = producer.redact_sbom()
print(f"SBOM redaction completed successfully? {str(ok)}")

# verify the redacted SBOM
redacted_sbom_tree = producer.get_redacted_sbom_tree()


# instantiate the consumer and decrypt the redacted SBOM
consumer = Consumer(sbom_file, redacted_sbom_tree)
consumer.decrypt_sbom()
print("decrypted tree signature verification passed")

# verify the sameness of the redacted and decrypted SBOM trees
passed = verify_sameness(redacted_sbom_tree, consumer.decrypted_sbom_tree)
print(f"full tree sameness verification passed? {str(ok)}")

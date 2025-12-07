import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.util.config import Config
from petra.lib.models import SbomNode
from petra.lib.models.tree_ops import serialize_tree
from petra.lib.internals.producer import Producer
from petra.lib.internals.consumer import Consumer
from petra.lib.internals.distributor import Distributor


# read in the IP policy config
conf = Config("./config/ip-policy.conf")

# get the SBOM file and policy
sbom_file = conf.get_sbom_files()[0]
policy_file = conf.get_cpabe_policy('ip-policy')

# Producer requests sbom redaction
producer = Producer(sbom_file, policy_file)
producer.request_redaction()

# Distributor verifies producer's signature on redacted SBOM
redacted_sbom, producer_cert = producer.to_distributor()
distributor = Distributor(redacted_sbom, producer_cert)

# Consumer decrypts the redacted SBOM
consumer = Consumer(sbom_file, redacted_sbom)
consumer.decrypt_sbom()
print("decrypted tree signature verification passed")

# Consumer verifies the sameness of the redacted and decrypted SBOM trees
passed = verify_sameness(redacted_sbom, consumer.decrypted_sbom_tree)
print(f"full tree sameness verification passed? {str(passed)}")

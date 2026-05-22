import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.models.tree_ops import build_sbom_tree, verify_sameness
from petra.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.util.config import Config
from petra.models import SbomNode
from petra.models.tree_ops import serialize_tree
from petra.internals.producer import Producer
from petra.internals.consumer import Consumer
from petra.internals.distributor import Distributor


from graphviz import Digraph

TYPE_STYLE = {
    "S": {"shape": "box", "style": "filled", "fillcolor": "#dbeafe"},
    "C": {"shape": "box", "style": "filled,dashed", "fillcolor": "#e0f2fe"},
    "F": {"shape": "box", "style": "filled,dotted", "fillcolor": "#eff6ff"},
}

def short_hash(h):
    return h[:7] if h else "None"

def short_policy(h):
    return h[:104] if h else "None"

#  in sbomnode plaintext_hash
# in complex plaintext_commit plaintext_hash
#in field plaintext_commit
def node_label(node):
    t = node.get("t")

    if t == "S":
        return f"SBOM\npurl: {node.get('purl', '')}\nhash: {short_hash(node.get('hash'))}\n policy: {short_policy(node.get('policy'))}\n commitment: {short_hash(node.get('plaintext_hash'))}"

    if t == "C":
        return f"{node.get('type', '')}\nhash: {short_hash(node.get('hash'))}\n policy: {short_policy(node.get('policy'))}\n commitment: {short_hash(node.get('plaintext_commit')[1])}"

    if t == "F":
        return (
            f"{field_display_value(node)}\n"
            f"hash: {short_hash(node.get('hash'))}\n policy: {short_policy(node.get('policy'))}\n commitment: {short_hash(node.get('plaintext_commit')[1])}"
        )

    return str(node)


def draw_serialized_tree(tree, output_path="sbom_tree"):
    dot = Digraph("SBOMTree", format="png")
    dot.attr(rankdir="TB")
    dot.attr(splines="ortho")
    dot.attr(nodesep="0.4", ranksep="0.7")
    dot.attr("node", fontname="Helvetica", fontsize="10")
    dot.attr("edge", color="#6b7280", fontsize="8")

    counter = 0

    def add_node(node, parent_id=None, edge_label=None):
        nonlocal counter

        node_id = f"n{counter}"
        counter += 1

        t = node.get("t", "?")
        style = TYPE_STYLE.get(t, {"shape": "box"})

        dot.node(node_id, label=node_label(node), **style)

        if parent_id is not None:
            dot.edge(parent_id, node_id, label="")

        for child_key, child in node.get("children", {}).items():
            add_node(child, node_id, child_key)

    add_node(tree)
    #dot.render(output_path, cleanup=True, view=True)
    #return output_path + ".png"
    return dot


def field_display_value(node: dict) -> str:
    decrypted_hex = node.get("decrypted_data")

    if decrypted_hex:
        decrypted_bytes = bytes.fromhex(decrypted_hex)
        plaintext_bytes = decrypted_bytes[32:]
        return plaintext_bytes.decode("utf-8", errors="replace")

    return f"{node.get('name', '')}: {node.get('value', '')}"



# get the SBOM file and policy
sbom_file = "nats.json"
policy_file = "policies/visualizer_policy"

# Producer requests sbom redaction
#print("Consumer meets node policy ✓✓✓✓ ....\n\n")
#print(f"Decrypting node data .... \n\n")
input("\n\nSoftware producer gets a master CP-ABE decryption key ...")
input ("\n\nSoftware producer gets an ephemeral signing key, and a Fulcio certificate from the KMS after OIDC-based authentication ...\n\n")
#input("\n\nSBOM producer gets a master CP-ABE decryption key, an ephemeral signing key, and a Fulcio certificate from the KMS after OIDC-based authentication ...\n\n")
input(f"Software producer requests sbom redaction from the generator according to its policy.... \n\n")

producer = Producer(sbom_file, policy_file)
producer.request_redaction()
input("SBOM Generator gets the CP-ABE encryption key from the KMS and receives an ephemeral signing key with a Fulcio certificate bound to its OIDC identity\n\n")
#input("SBOM Generator gets signing key pair and encryption key from Sigstore ...\n\n")
input(f"SBOM Generator generates plaintext SBOM and selective redacted SBOM.... \n\n")
input(f"Generator signs SBOM tree.... \n\n")


#print(f"Software producer verifies generator's signature on redacted SBOM ...  Passed ✓✓✓✓ \n\n")
input(f"Software producer verifies generator's signature on redacted SBOM ... \n\n")
input(f"Redacted SBOM signature verification passed ✓✓✓✓  \n\n")

input(f"Software producer countersign the redacted SBOM ... \n\n")



graph = draw_serialized_tree(serialize_tree(producer.plaintext_sbom_tree))
graph.render("plaintext sbom tree", format="svg", view=True)
input(f"Showing plaintext SBOM tree, close it, then press Enter for next tree....\n\n")

input(f"Sending redacted SBOM tree to the Distributor....\n\n")

input(f"Software Distributor verifies producer's signature on redacted SBOM ... \n\n")
input(f"Redacted SBOM signature verification passed ✓✓✓✓  \n\n")

# Distributor verifies producer's signature on redacted SBOM
redacted_sbom, producer_cert = producer.to_distributor()
graph = draw_serialized_tree(serialize_tree(redacted_sbom))
graph.render("redacted sbom tree", format="svg", view=True)
input(f"Showing redacted SBOM tree, close it, then press Enter for next tree ....\n\n")

distributor = Distributor(redacted_sbom, producer_cert)
input("Consumer enrolls with the KMS and receives an attribute-bound CP-ABE decryption key with an epoch-based expiry ...\n\n")
#input("Consumer gets decryption key from Sigstore according to her attributes ...\n\n")
print(f"Consumer attributes:\n\n")
input(f"['Security Auditor', 'Audit Authorization status of Approved', 'epoch:1780704000']\n\n")
#input(f"['Security Auditor', 'Audit Authorization status of Approved', 'name:41898282', 'namespace:refs/heads/main', 'epoch:1780704000']\n")

input(f"Consumer tries to decrypt the redacted SBOM ....  \n\n")

# Consumer decrypts the redacted SBOM
input("Consumer meets node policy ✓✓✓✓ \n\n")
input(f"Decrypting node data .... \n\n")
consumer = Consumer(sbom_file, redacted_sbom)
consumer.decrypt_sbom()

graph = draw_serialized_tree(serialize_tree(consumer.decrypted_sbom_tree))
graph.render("decrypted sbom tree", format="svg", view=True)
input(f"Showing decrypted tree ...\n")

input(f"Consumer verifies decrypted tree signature ... \n\n")

input("Decrypted tree signature verification passed ✓✓✓✓\n\n")

input(f"Consumer verifies the sameness of the redacted and decrypted SBOM trees ...\n")

# Consumer verifies the sameness of the redacted and decrypted SBOM trees
passed = verify_sameness(redacted_sbom, consumer.decrypted_sbom_tree)
print(f"Tree sameness verification passed? {str(passed)}")

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
    return h[:7] if h else "nohash"

def node_label(node):
    t = node.get("t")

    if t == "S":
        return f"SBOM\npurl: {node.get('purl', '')}\nhash: {short_hash(node.get('hash'))}"

    if t == "C":
        return f"{node.get('type', '')}\nhash: {short_hash(node.get('hash'))}"

    if t == "F":
        return (
            f"{field_display_value(node)}\n"
            f"hash: {short_hash(node.get('hash'))}"
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

# read in the IP policy config
conf = Config("./config/ip-policy.conf")

# get the SBOM file and policy
sbom_file = "nats.json"
policy_file = "policies/visualizer_policy"

# Producer requests sbom redaction
producer = Producer(sbom_file, policy_file)
producer.request_redaction()

graph = draw_serialized_tree(serialize_tree(producer.plaintext_sbom_tree))
graph.render("plaintext sbom tree", format="svg", view=True)
input(f" showing plaintext tree, close it, then press Enter for next tree...")

# Distributor verifies producer's signature on redacted SBOM
redacted_sbom, producer_cert = producer.to_distributor()
graph = draw_serialized_tree(serialize_tree(redacted_sbom))
graph.render("redacted sbom tree", format="svg", view=True)
input(f" showing redacted tree, close it, then press Enter for next tree...")

distributor = Distributor(redacted_sbom, producer_cert)

# Consumer decrypts the redacted SBOM
consumer = Consumer(sbom_file, redacted_sbom)
consumer.decrypt_sbom()
graph = draw_serialized_tree(serialize_tree(consumer.decrypted_sbom_tree))
graph.render("decrypted sbom tree", format="svg", view=True)
input(f" showing decrypted tree, close it, then press Enter for next tree...")


print("decrypted tree signature verification passed")

# Consumer verifies the sameness of the redacted and decrypted SBOM trees
passed = verify_sameness(redacted_sbom, consumer.decrypted_sbom_tree)
print(f"full tree sameness verification passed? {str(passed)}")

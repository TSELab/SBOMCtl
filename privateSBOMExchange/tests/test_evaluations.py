import configparser
import copy
import os
import sys
import time
import json
from tqdm import tqdm
from lib4sbom.parser import SBOMParser
import configparser
from multiprocessing import Pool

from ..src.petra.lib.models import *
import cpabe

"""This tests whether a target has is a member of a tree 
"""

config = configparser.ConfigParser()
config.read('testConfigs/config.ini')
 
target_sbom_dir = config['DEFAULT']['small_target_sbom']
results_dir = config['DEFAULT']['results']

os.makedirs(results_dir, exist_ok=True)


Groups = [["Security Auditor", "Audit Authorization status of Approved"], ["Security Analyst", "Confidential Security Clearance Level" ]]


pk, mk = cpabe.cpabe_setup();
sk = cpabe.cpabe_keygen(pk, mk, Groups[1])

# too wide, to many nodes to verify membership for. For function tests, skip
too_wide_sboms = []

policy_files = [config['POLICY'][key] for key in ("intellectual_property_policy", "weaknesses_policy")]
write_to = os.path.join(results_dir, "performance.json")

DEBUG = True
def log(s):
    if DEBUG:
        print(s)

def build_tree(sbom):
    return build_sbom_tree(sbom)

def hash_tree_node(sbom_tree):
    # hash nodes in the tree
    merkle_visitor = MerkleVisitor()
    merkle_root_hash = sbom_tree.accept(merkle_visitor)

def get_tree_node_hashes(sbom_tree):
    hash_hunter = GetTargetNodes()
    sbom_tree.accept(hash_hunter)
    target_hashes = hash_hunter.get_hashes()
    return target_hashes

def encrypt_contents(sbom_tree,pk,Policy):
    encrypt_visitor = EncryptVisitor(pk,Policy)
    sbom_tree.accept(encrypt_visitor)

def decrypt_contents(sbom_tree, sk):
    decrypt_visitor = DecryptVisitor(sk)
    redacted_tree = copy.deepcopy(sbom_tree)
    redacted_tree.accept(decrypt_visitor)

def process_sbom(sbom_file):
    sbom_file = os.path.join(target_sbom_dir, sbom_file)
    sbom_file_size = os.path.getsize(os.path.join(target_sbom_dir, sbom_file))
    

    # Parse SPDX data into a Document object
    SBOM_parser = SBOMParser()   
    SBOM_parser.parse_file(sbom_file)   
    sbom=SBOM_parser.sbom

    start_time = time.time()
    sbom_tree = build_tree(sbom)
    build_tree_time = time.time() - start_time
    

    start_time = time.time()
    hash_tree_node(sbom_tree)
    hash_time = time.time() - start_time

    tree_nodes = get_tree_node_hashes(sbom_tree)

    start_time = time.time()
    encrypt_contents(sbom_tree,pk,policy_files[1])
    encrypt_time = time.time() - start_time


    tree_nodes_count = len(tree_nodes)

    start_time = time.time()
    decrypt_contents(sbom_tree, sk)
    decrypt_time = time.time() - start_time

    to_store = {
        "file_size": sbom_file_size,
        "build_tree_time": build_tree_time,
        "hash_time": hash_time,
        "encrypt_time": encrypt_time,
        "decrypt_time": decrypt_time,
        "tree_nodes_count": tree_nodes_count,
    }

    store_data(to_store)

def store_data(performance_data, file=write_to):
    with open(file, 'a') as file:
        file.write(json.dumps(performance_data) + "\n")

if __name__ == "__main__":
    # reset file for new test
    if os.path.exists(write_to):
        os.remove(write_to)

    target_sboms = os.listdir(target_sbom_dir)
    total_processed = len(target_sboms)

    print("Started processing sboms....")
    with Pool(processes=os.cpu_count()) as pool:
        pool.map(process_sbom, target_sboms)


    log(f"\nAll {total_processed} sboms processed")




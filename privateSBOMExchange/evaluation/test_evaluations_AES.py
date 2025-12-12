import configparser
import copy
import os
import time
import json
from tqdm import tqdm
from lib4sbom.parser import SBOMParser
import configparser
from multiprocessing import Pool
from pympler import asizeof

from petra.models.tree_ops import build_sbom_tree
from petra.models import *
from petra.models.tree_ops import GetTargetNodes
import cpabe



config = configparser.ConfigParser()
config.read('config/config.ini')
 
target_sbom_dir = config['DEFAULT']['target_sbom_dir']
results_dir = config['DEFAULT']['results']

os.makedirs(results_dir, exist_ok=True)


#Groups = [["Security Auditor", "Audit Authorization status of Approved"], ["Security Analyst", "Confidential Security Clearance Level" ]]
Groups = [["Security Analyst", "works at DoD","epoch:1767744000"], ["Security Analyst", "Confidential Security Clearance Level","epoch:1767744000" ]]


pk, mk = cpabe.cpabe_setup();

# too wide, to many nodes to verify membership for. For function tests, skip
too_wide_sboms = []

policy_files = [config['POLICY'][key] for key in ("intellectual_property_policy", "weaknesses_policy")]

DEBUG = True
def log(s):
    if DEBUG:
        print(s)

def build_tree(sbom, policy):
    time_tree="(\"epoch:1767744000\")"
    return build_sbom_tree(sbom,time_tree,policy)

def hash_tree_node(sbom_tree):
    # hash nodes in the tree
    merkle_visitor = MerkleVisitor()
    merkle_root_hash = sbom_tree.accept(merkle_visitor)

def get_tree_node_hashes(sbom_tree):
    hash_hunter = GetTargetNodes()
    sbom_tree.accept(hash_hunter)
    target_hashes = hash_hunter.get_hashes()
    return target_hashes

def encrypt_contents(sbom_tree,pk):
    encrypt_visitor = EncryptVisitor(pk)
    sbom_tree.accept(encrypt_visitor)
    # print("done encrypting")
    return sbom_tree

def decrypt_contents(sbom_tree, sk):
    # decrypt_visitor = ParallelDecryptVisitor(sk)
    decrypt_visitor = DecryptVisitor(sk)
    sbom_tree.accept(decrypt_visitor)
    # decrypt_visitor.finalize()
    return sbom_tree

def process_sbom(sbom_file,policy,policy_number):
    sbom_file = os.path.join(target_sbom_dir, sbom_file)
    sbom_file_size = os.path.getsize(sbom_file)
    

    # Parse SPDX data into a Document object
    SBOM_parser = SBOMParser()   
    try:
        SBOM_parser.parse_file(sbom_file)   
    except:
        log(sbom_file)
        return
    sbom=SBOM_parser.sbom

    start_time = time.time()
    sbom_tree = build_tree(sbom, policy)
    build_tree_time = time.time() - start_time
    sbom_tree_storage = asizeof.asizeof(sbom_tree)
    

    start_time = time.time()
    hash_tree_node(sbom_tree)
    hash_time = time.time() - start_time

    tree_nodes = get_tree_node_hashes(sbom_tree)

    start_time = time.time()
    #encrypt_contents(sbom_tree,pk,policy_files[1])
    encrypted_tree = encrypt_contents(sbom_tree,pk)
    encrypt_time = time.time() - start_time
    encrypted_tree_storage = asizeof.asizeof(encrypted_tree)


    redacted_tree = copy.deepcopy(sbom_tree)
    tree_nodes_count = len(tree_nodes)

    sk = cpabe.cpabe_keygen(pk, mk, Groups[policy_number])

    start_time = time.time()
    decrypted_tree = decrypt_contents(redacted_tree, sk)
    decrypt_time = time.time() - start_time
    decrypted_tree_storage = asizeof.asizeof(decrypted_tree)

    to_store = {
        "file_size": sbom_file_size,
        "build_tree_time": build_tree_time,
        "hash_time": hash_time,
        "encrypt_time": encrypt_time,
        "decrypt_time": decrypt_time,
        "tree_nodes_count": tree_nodes_count,
        "sbom_tree_storage": sbom_tree_storage,
        "encrypted_tree_storage": encrypted_tree_storage,
        "decrypted_tree_storage": decrypted_tree_storage,
        "policy": policy.split('/')[-1]
    }
    write_to = os.path.join(results_dir, f"performance_{policy.split('/')[-1]}.json")
    store_data(to_store,write_to)

def store_data(performance_data, write_to):
        
    with open(write_to, 'a') as file:
        file.write(json.dumps(performance_data) + "\n")

if __name__ == "__main__":
    # reset file for new test

    for policy_number, policy in enumerate(policy_files):
        print("\n" + "=" * 60)
        print(f"Processing policy: {policy}")
        print("=" * 60)

        target_sboms = os.listdir(target_sbom_dir)
        total_processed = len(target_sboms)

        print("Started processing sboms....")
    #    with Pool(processes=os.cpu_count()) as pool:
    #       pool.map(process_sbom, target_sboms)
    
        write_to = os.path.join(results_dir, f"performance_{policy.split('/')[-1]}.json")
        if os.path.exists(write_to):
            os.remove(write_to)
        for sbom in tqdm(target_sboms , desc="Evaluating SBOMs"):
            process_sbom(sbom,policy,policy_number)

        log(f"\nAll {total_processed} sboms processed")


import configparser
import copy
import sys
import os
import configparser
import filecmp
from difflib import unified_diff
from lib4sbom.parser import SBOMParser

from ..src.petra.lib.models import *
import cpabe
"""This tests encryption and decryption based on policy and attributes 
"""
def show_differences(file1, file2):
    with open(file1, 'r') as f1, open(file2, 'r') as f2:
        f1_lines = f1.readlines()
        f2_lines = f2.readlines()

        diff = unified_diff(f1_lines, f2_lines, fromfile=file1, tofile=file2)
        
        for line in diff:
            print(line, end='')

def print_visitor_to_file(function, sbom_tree, filename):
    """ Redirecting print output to a file"""
    with open(filename, 'w') as file:
        original_stdout = sys.stdout
        try:
            sys.stdout = file
            
            print("Printing raw SBOM tree")
            print_visitor = function()
            sbom_tree.accept(print_visitor)
        finally:
            sys.stdout = original_stdout

def cleanup():
    for file in ("build_output_tree.txt","hash_output_tree.txt","encrypt_output_tree.txt", "decrypt_output_tree.txt"):
        if os.path.exists(file):
            os.remove(file)


config = configparser.ConfigParser()
config.read('testConfigs/config.ini')
target_sbom_dir = config['DEFAULT']['target_sbom']
policy_files = [config['POLICY'][key] for key in ("intellectual_property_policy", "weaknesses_policy")]

sample_short_sbom = "spdx-syft-ibmcom_kubedns-sha256:c12a28611a6883a2879b8f8dae6a7b088082d40262a116be51c8ee0b69cf91e0.json"
sbom_file = os.path.join(target_sbom_dir, sample_short_sbom)

Groups = ["Security Auditor", "Audit Authorization status of Approved"]
pk, mk = cpabe.cpabe_setup();
sk = cpabe.cpabe_keygen(pk, mk, Groups)

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 
SBOM_parser.parse_file("./sbom_data/bom-shelter-test/julia.spdx_short.json") 
  
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)
print_visitor_to_file(PrintFieldNode, sbom_tree,"build_output_tree.txt")

merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)
merkle_root_hash_hex = merkle_root_hash.hex()
print("Merkle Root Hash for SBOM:", merkle_root_hash_hex)
print_visitor_to_file(PrintVisitor, sbom_tree,"hash_output_tree.txt")

for i, policy_file in enumerate(policy_files):

    encrypt_visitor = EncryptVisitor(pk,policy_file)
    sbom_tree.accept(encrypt_visitor)
    print("done encrypting")
    print_visitor_to_file(PrintVisitor,sbom_tree, "encrypt_output_tree.txt")

    merkle_visitor = MerkleVisitor()
    redacted_merkle_root_hash = sbom_tree.accept(merkle_visitor)
    redacted_merkle_root_hash_hex = merkle_root_hash.hex()

    decrypt_visitor = DecryptVisitor(sk)
    redacted_tree = copy.deepcopy(sbom_tree)
    redacted_tree.accept(decrypt_visitor)
    print("done decrypting")
    print_visitor_to_file(PrintFieldNode, redacted_tree, "decrypt_output_tree.txt")


    files_are_equal = filecmp.cmp("build_output_tree.txt", "decrypt_output_tree.txt", shallow=False)

    if not files_are_equal:
        print("SBOM mismatch. Worry only if keys have full decrypt attributes.")
        show_differences("build_output_tree.txt", "decrypt_output_tree.txt")


cleanup() #deletes created output files


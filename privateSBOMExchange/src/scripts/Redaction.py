from __future__ import print_function
import argparse
#import pyopenabe
from ctypes import *
import os
from traceback import print_tb
from unittest import result
from typing import Union

from smt.tree import TreeMapStore, TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof

from petra.lib.database import (get_session, SBOM, SMTNode, SMTValue, 
                                retrieve_sbom_as_tree_from_db, store_SBOM_as_tree_in_db)
from petra.lib.sbom import flatten_SPDX
from petra.lib.models import SBOM_as_tree, try_tree
from petra.lib.crypto import encrypt_SBOM, decrypt_SBOM_field, generate_user_private_key, init_abe

     
def make_args(cmd):
    args = cmd.encode().split()
    return (c_char_p * len(args))(*args)
  
def compare_stored_and_retrieved_tree(original,retrieved):
    assert original.store.nodes==retrieved.store.nodes
    assert original.store.values==retrieved.store.values
    return True

IN_THE_WILD_SPDX = "../../sbom_data/bom-shelter/in-the-wild/spdx"

    
def main():

    sboms_in_db=[]
    s = []
    parser = argparse.ArgumentParser(
                    prog='Redactor',
                    description='',
                    epilog='')
    parser.add_argument('-s','--sbom')           
    parser.add_argument('-p', '--policy') 
    parser.add_argument('-v', '--verbose')
    args = parser.parse_args()

    #test/data/SPDX/julia.spdx.json
    #SBOM_file_name=str(args.sbom)
 
    SBOM_file_name="julia.spdx.json"
    SBOM_file_path=IN_THE_WILD_SPDX + "/"+SBOM_file_name

    policy_file_name=args.policy
    #represent the SBOM in the SBOM_file_name as a Merkle Tree
    flatten_SBOM_data, sbom_file_encoding = flatten_SPDX(SBOM_file_path)
    sbom_tree, name = SBOM_as_tree(flatten_SBOM_data,sbom_file_encoding)
    trees={}
    tree_name = f"{name}"  # Create tree name
    trees[tree_name] =sbom_tree
    print(trees)

    #using tree stucture, store sbom as tree in sqlalchemy db
    t1=try_tree()
    
    store_SBOM_as_tree_in_db(sbom_tree,sbom_tree.get(b"name"))      
    retrieved_tree=retrieve_sbom_as_tree_from_db(sbom_tree.get(b"name"))  
    if compare_stored_and_retrieved_tree(sbom_tree,retrieved_tree):
        print("The Trees are identical in structures and nodes")

    #testing CP-ABE setup algorithim
    print("\n\nSetting up CP-abe parameters")
    pubkey, masterkey = init_abe()

    print("\n\nTesting CP-ABE encrypt ....")
    policy = '"AUTHOR" or "FEDRAMP"'
    bundle = encrypt_SBOM(flatten_SBOM_data, pubkey, policy)

    #testing CP-ABE key generation algorithim
    print("\n\nTesting CP-ABE key generation ....")
    roles = ["FEDRAMP"]
    sk = generate_user_private_key(pubkey, masterkey, roles)

    #testing CP-ABE decrypt algorithim
    print("\n\nTesting CP-ABE decrypt ....")
    pt = decrypt_SBOM_field(bundle, "dataLicense", sk)
    print("Decrypted target field: {}".format(pt))


if __name__ == "__main__":
    main()





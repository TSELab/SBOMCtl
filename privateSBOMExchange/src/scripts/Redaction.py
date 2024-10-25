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
from petra.lib.crypto import encrypt_SBOM, decrypt_SBOM_field, generate_user_private_key

     
def make_args(cmd):
    args = cmd.encode().split()
    return (c_char_p * len(args))(*args)
  
def compare_stored_and_retrieved_tree(original,retrieved):
    assert original.store.nodes==retrieved.store.nodes
    assert original.store.values==retrieved.store.values
    return True

    
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
 
    #  path of submodules data 
    in_the_lab_spdx="../../sbom_data/bom-shelter/in-the-lab/spdx-popular-containers/data"
    in_the_wild_cyclonedx="../../sbom_data/bom-shelter/in-the-wild/cyclonedx"
    in_the_wild_spdx = '../../sbom_data/bom-shelter/in-the-wild/spdx' 


    SBOM_file_name="julia.spdx.json"
    SBOM_file_path=in_the_wild_spdx+"/"+SBOM_file_name

    policy_file_name=args.policy
    #represent the SBOM in the SBOM_file_name as a Merkle Tree
    flatten_SBOM_data,sbom_file_encoding = flatten_SPDX(SBOM_file_path)
    sbom_tree,name=SBOM_as_tree(flatten_SBOM_data,sbom_file_encoding)
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


    cpabe_setup_file = "petra/lib/cpabe-setup.so"
    cpabe_keygen_file = "petra/lib/cpabe-keygen.so"
    cpabe_enc_file = "petra/src/lib/cpabe-enc.so"
    cpabe_dec_file = "petra/lib/cpabe-dec.so"


    #testing CP-ABE setup algorithim
    
    print("\n\nTesting CP-ABE setup ....")
    cpabe_setup_functions = CDLL(cpabe_setup_file)
    cpabe_setup_functions.main()

    #testing CP-ABE encrypt algorithim
    print(os.getpid())
 
    print("\n\nTesting CP-ABE encrypt ....")
    encrypt_SBOM(flatten_SBOM_data, cpabe_enc_file)

    #testing CP-ABE key generation algorithim
    print("\n\nTesting CP-ABE key generation ....")
    generate_user_private_key(cpabe_keygen_file)

    #testing CP-ABE decrypt algorithim
    print("\n\nTesting CP-ABE decrypt ....")

    #cpabe-dec PUB_KEY PRIV_KEY FILE
    decrypt_SBOM_field(cpabe_dec_file,"dataLicense","pub_key","priv_key")


if __name__ == "__main__":
    main()





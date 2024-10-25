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


     
def make_args(cmd):
    args = cmd.encode().split()
    return (c_char_p * len(args))(*args)



  
def decrypt_SBOM_field(cpabe_dec_file,field_name,pub_key,priv_key):
    args = make_args(f"3 {pub_key} {priv_key} {field_name}.cpabe")
    print(*args)
        
    cpabe_decrypt_functions = CDLL(cpabe_dec_file)
    cpabe_decrypt_functions.main.restype = c_int
    cpabe_decrypt_functions.main.argtypes = c_int,POINTER(c_char_p)
    cpabe_decrypt_functions.main(len(args), args)
    cpabe_decrypt_functions.reset_globals()

def generate_user_private_key(cpabe_keygen_file,priv_key,pub_key,master_key,user_attributes):
    cpabe_keygen_functions = CDLL(cpabe_keygen_file)

    cpabe_keygen_functions.main.restype = c_int
    cpabe_keygen_functions.main.argtypes = c_int,POINTER(c_char_p)
    #cpabe-keygen -o sara_priv_key pub_key master_key test/policy

    args = make_args(f'5 -o {priv_key} {pub_key} {master_key} {user_attributes}')
    print(*args)
    cpabe_keygen_functions.main(len(args), args)

def encrypt_SBOM(flatten_SBOM_data, cpabe_enc_file,pub_key,policy):
    
    #ToDo: policy needs to be splitted for each field
    cpabe_encrypt_functions = CDLL(cpabe_enc_file)
    print(type(cpabe_encrypt_functions))
    cpabe_encrypt_functions.main.restype = c_int
    cpabe_encrypt_functions.main.argtypes = c_int,POINTER(c_char_p)     

    for key,value in flatten_SBOM_data.items():
        with open (key,"w") as SBOM_field_file:
            if isinstance(value, bool):
                value=str(value)
            SBOM_field_file.write(value)                     
        args = make_args(f"3 {pub_key} {key} {policy}")
        print(*args)
        cpabe_encrypt_functions.main(len(args), args)
        cpabe_encrypt_functions.reset_globals()

def  compare_stored_and_retrieved_tree(original,retrieved):
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





from __future__ import print_function
import argparse
#import pyopenabe
from ctypes import *
import os
import sqlite3
from traceback import print_tb
from unittest import result
import boolean
from lib4sbom.parser import SBOMParser
from typing import Union


from sqlalchemy import MetaData
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from smt.tree import TreeMapStore,TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof

import json
import pandas

from spdx_tools.spdx.model import (Checksum, ChecksumAlgorithm, File, FileType, Relationship, RelationshipType)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file


def prove(tree,SBOMField):
    for item in SBOMField:
        proof = tree.prove(item)
        assert proof.sanity_check()
        assert verify_proof(proof,tree.root, item, SBOMField[item] )


def flatten_data(y):
    out = {}
    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out

#represent SBOM in file as Merkle tree
def SBOM_as_tree(flatten_SBOM_data,sbom_file_encoding):
    tree = SparseMerkleTree(store=TreeMemoryStore())
    tree_name=""
    count=0
    # add each SBOM field to the tree
    for field_name,value in flatten_SBOM_data.items():
        count+=1
        SBOMField={field_name:value}
        if field_name =="name":
            tree_name=value
        #print(SBOMField)
        assert DEFAULTVALUE == tree.get(b"")
        for item in SBOMField:
            if isinstance(SBOMField[item], bool):
                SBOMField[item]=str(SBOMField[item])
            root1 = tree.update(item.encode(sbom_file_encoding), SBOMField[item].encode(sbom_file_encoding))
            assert 32 == len(root1)
            assert root1 != PLACEHOLDER
        
    return tree,tree_name

def flatten_SPDX(file_name):
    with open (file_name, 'r') as sbom_file:
        sbom_file_encoding=sbom_file.encoding
        sbom_data = json.load(sbom_file)
        result = {}
        #parsed_data = parse_json(data,result,"")
        flatten_sbom=flatten_data(sbom_data)
    return flatten_sbom ,sbom_file_encoding


Base = declarative_base()
class SBOM(Base):
        __tablename__ = 'sbom'
        
        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False,unique=True)
        root_hash = Column(String, nullable=False)
        created_at = Column(TIMESTAMP, server_default=func.now())
class SMTNode(Base):
        __tablename__ = 'smt_nodes'
        sbom_id = Column(Integer, ForeignKey('sbom.id'))
        key = Column(String, nullable=False,primary_key=True)
        value = Column(String, nullable=False)
        #parent_hash = Column(String)
class SMTValue(Base):
        __tablename__ = 'smt_values'
        sbom_id = Column(Integer, ForeignKey('sbom.id'))
        key = Column(String, nullable=False,primary_key=True)
        value = Column(String, nullable=False)
        #parent_hash = Column(String)
      
def make_args(cmd):
    args = cmd.encode().split()
    return (c_char_p * len(args))(*args)


def try_tree():
    t=SparseMerkleTree(store=TreeMemoryStore())
    roota= t.update(b"a",b"a1")
    assert 32 == len(roota)
    assert roota !=PLACEHOLDER
    assert t.update(b"b",b"b2")
    assert DEFAULTVALUE == t.get(b"d")
    assert b"b2"== t.get(b"b")
    proof = t.prove(b"b")
    assert verify_proof(proof, t.root, b"b", b"b2")

    return t


def store_SBOM_as_tree_in_db(tree_to_store,sbom_name):
  
    added_sbom=add_or_get_to_db(SBOM,name=sbom_name,root_hash=tree_to_store.root_as_bytes())
    session.flush()
    id = added_sbom.id
    for k,v in tree_to_store.store.nodes.items():
        added_node=add_or_get_to_db(SMTNode,sbom_id=id,key=k,value=v)
        session.flush()        
    for k,v in tree_to_store.store.values.items():
        added_value=add_or_get_to_db(SMTValue,sbom_id=id,key=k,value=v)
        session.flush()        

def add_or_get_to_db(table, **kwargs):
    # Try to find the record
    record = session.query(table).filter_by(**kwargs).first()
    if record:
        print(f"Record exists")
        return record
    else:
        new_record=table(**kwargs)
        # If it doesn't exist, create a new record
        session.add(new_record)
        session.commit()
        print(f"Record added")
        return new_record

def retrieve_sbom_as_tree_from_db(sbom_name):
    sbom = session.query(SBOM).filter_by(name=sbom_name).first()

    nodes=dict()
    values=dict()
    if sbom:
        print(sbom.id,sbom.name,sbom.root_hash)
        root=sbom.root_hash
    smt_nodes = session.query(SMTNode).filter_by(sbom_id=sbom.id)
    smt_vals = session.query(SMTValue).filter_by(sbom_id=sbom.id)
    for response in smt_nodes.all():
        nodes[response.key]=response.value
        print(response.sbom_id,response.key,response.value)
    for response in smt_vals.all():
        values[response.key]=response.value
        print(response.sbom_id,response.key,response.value)
    retrived_tree=SparseMerkleTree(store=TreeMemoryStore())
    memorystore=TreeMemoryStore()
    memorystore.nodes=nodes
    memorystore.values=values
    retrived_tree.store=memorystore
    retrived_tree.root=root
    return retrived_tree
   
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
    in_the_lab_spdx="../sbom_data/bom-shelter/in-the-lab/spdx-popular-containers/data"
    in_the_wild_cyclonedx="../sbom_data/bom-shelter/in-the-wild/cyclonedx"
    in_the_wild_spdx = '../sbom_data/bom-shelter/in-the-wild/spdx' 


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

    

    #using tree stucture, store sbom as tree in sqlalchamey db
    t1=try_tree()
    
    store_SBOM_as_tree_in_db(sbom_tree,sbom_tree.get(b"name"))      
    retrieved_tree=retrieve_sbom_as_tree_from_db(sbom_tree.get(b"name"))  
    if compare_stored_and_retrieved_tree(sbom_tree,retrieved_tree):
        print("The Trees are identical in structures and nodes")


    cpabe_setup_file = "src/lib/cpabe-setup.so"
    cpabe_keygen_file = "src/lib/cpabe-keygen.so"
    cpabe_enc_file = "src/lib/cpabe-enc.so"
    cpabe_dec_file = "sr    c/lib/cpabe-dec.so"


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



 
# Create a database engine
engine = create_engine('sqlite:///dfsddff.db')  # Use SQLite for this example

# Create the table in the database
Base.metadata.create_all(engine)

# Create a session
Session = sessionmaker(bind=engine)
session = Session()   
if __name__ == "__main__":
    main()





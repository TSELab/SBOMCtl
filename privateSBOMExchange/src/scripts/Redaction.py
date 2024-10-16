from __future__ import print_function
import argparse
#import pyopenabe
from ctypes import *
import os
from lib4sbom.parser import SBOMParser
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
import json
import pandas
from spdx_tools.spdx.model import (Checksum, ChecksumAlgorithm, File, 
                                   FileType, Relationship, RelationshipType)
from spdx_tools.spdx.parser.parse_anything import parse_file

from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file

def addtoTree(tree,SBOMField):

    assert DEFAULTVALUE == tree.get(b"c")
    for item in SBOMField:
        root1 = tree.update(item.encode("utf-8"), SBOMField[item].encode("utf-8"))
        assert 32 == len(root1)
        assert root1 != PLACEHOLDER

def prove(tree,SBOMField):
    for item in SBOMField:
        proof = tree.prove(item)
        assert proof.sanity_check()
        assert verify_proof(proof,tree.root, item, SBOMField[item] )

def dict_generator(indict, pre=None):
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                for d in dict_generator(value, pre + [key]):
                    yield d
            elif isinstance(value, list) or isinstance(value, tuple):
                for v in value:
                    for d in dict_generator(v, pre + [key]):
                        yield d
            else:
                yield pre + [key, value]
    else:
        yield pre + [indict]
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
def parse_json(data,result,new_key):

    for key, value in data.items():
        if isinstance(value, dict):
            #result[key] = parse_json(value,result)
            parse_json(value,result,key)

        else:
            result[new_key+key] = value
            
        if isinstance(value, list):
            #print(new_key+key)
            #print(key,"list")
            for key in value:
                if isinstance(value, dict):
                    #result[key] = parse_json(value,result)
                    parse_json(value,result,key)
                else:
                    result[new_key+key] = value
                

                

    #print (result)
    new_key=""
    return result

#represent SBOM in file as Merkle tree
def SBOMAsTree(file_name):
    flatten_SBOM_data = Flatten_spdx(file_name)
    tree = SparseMerkleTree()
    count=0
    # add each SBOM field to the tree
    for field_name,SBOMField in flatten_SBOM_data.items():
        count+=1
        SBOMField={field_name:field_name}
        addtoTree(tree,SBOMField)
    return tree

def Flatten_spdx(file_name):
    with open (file_name, 'r') as sbom_file:
        sbom_data = json.load(sbom_file)
        result = {}
        #parsed_data = parse_json(data,result,"")
        flatten_sbom=flatten_data(sbom_data)
    return flatten_sbom

#setup CP-ABE algorithim
def SetupCPABE():
    openabe = pyopenabe.PyOpenABE()
    cpabe = openabe.CreateABEContext("CP-ABE")
    cpabe.generateParams()
    return cpabe

#Encrypt SBOMField over an access policy using CPE-ABE Encrypt algorithim 
def EncryptCPABE (plaintext,cpabe, accessPolicy):
    cipherText = cpabe.encrypt(accessPolicy, plaintext)
    print("ABE cipherText: ", len(cipherText))
    return cipherText

#Decrypt SBOMField for a given identity using CPE-ABE Decrypt algorithim 
def DecryptCPABE (cpabe, cipherText,identity):    
    recoveredPlaintext = cpabe.decrypt(identity, cipherText)
    print("Plaintext: ", recoveredPlaintext)
    return recoveredPlaintext

#Generate Key for a given identity using CPE-ABE Key Generation algorithim
def GenerateKeyCPABE(cpabe, attributes , identity):
    cpabe.keygen(attributes, identity)

def cpabe_openabe(policy_file_name,plaintext):
    #testing CP-ABE setup algorithim
    
    print("\n\nTesting CP-ABE setup ....")
    cpabe=SetupCPABE()
    
    #testing CP-ABE Encrypt algorithim
    print("\n\nTesting CP-ABE Encrypt ....")
    
    #parse access policy file
    #arg: test/data/policy   
    with open(policy_file_name,'rt') as policy_file:
        accessPolicy=policy_file.read()
        #accessPolicy="((one or two) and three)"
        
        #for item in the Merkle Tree, get the SBOM field and Encrypt it 
        sbom_field = b"SBOM-Field"
        cipherText_field=EncryptCPABE(sbom_field,cpabe,accessPolicy)
        
    print("Testing CP-ABE GenerateKey")
    attributes= "|two|three|"
    identity= "alice"
    GenerateKeyCPABE(cpabe, attributes , identity)

    print("Testing CP-ABE Decrypt")
    identity="alice"
    recovered_SBOM_field=DecryptCPABE(cpabe, cipherText_field,identity)
    assert sbom_field == recovered_SBOM_field, "Didn't recover the message!"

    
    print("Testing key import")
    msk = cpabe.exportSecretParams()
    mpk = cpabe.exportPublicParams()
    uk = cpabe.exportUserKey("alice")

    cpabe2 = openabe.CreateABEContext("CP-ABE")

    cpabe2.importSecretParams(msk)
    cpabe2.importPublicParams(mpk)
    cpabe2.importUserKey("alice", uk)

    pt2 = cpabe2.decrypt("alice", cipherText_field)
    print("PT: ", pt2)
    assert plaintext == pt2, "Didn't recover the message!"
def main():
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
    in_the_lab_spdx="sbom_data/bom-shelter/in-the-lab/spdx-popular-containers/data"
    in_the_wild_cyclonedx="sbom_data/bom-shelter/in-the-wild/cyclonedx"
    in_the_wild_spdx = 'sbom_data/bom-shelter/in-the-wild/spdx' 

    SBOM_file_name="julia.spdx.json"
    SBOM_file_path=in_the_wild_spdx+"/"+SBOM_file_name

    policy_file_name=args.policy
    #represent the SBOM in the SBOM_file_name as a Merkle Tree
    tree=SBOMAsTree(SBOM_file_path)
    
    cpabe_setup_file = "privateSBOMExchange/src/lib/cpabe-setup.so"
    cpabe_keygen_file = "privateSBOMExchange/src/lib/cpabe-keygen.so"
    cpabe_enc_file = "privateSBOMExchange/src/lib/cpabe-enc.so"
    cpabe_dec_file = "privateSBOMExchange/src/lib/cpabe-dec.so"


    #testing CP-ABE setup algorithim
    
    print("\n\nTesting CP-ABE setup ....")
    cpabe_setup_functions = CDLL(cpabe_setup_file)
    print(type(cpabe_setup_functions))
    cpabe_setup_functions.main()

    #testing CP-ABE encrypt algorithim
    
    print("\n\nTesting CP-ABE encrypt ....")
    cpabe_encrypt_functions = CDLL(cpabe_enc_file)
    print(type(cpabe_encrypt_functions))
    cpabe_encrypt_functions.main.restype = c_int
    cpabe_encrypt_functions.main.argtypes = c_int,POINTER(c_char_p)

    def make_args(cmd):
        args = cmd.encode().split()
        return (c_char_p * len(args))(*args)

    args = make_args('3 pub_key flatten_sbom foo')
    print(*args)
    print(os.getpid())
    #backup the file before deletion
    cpabe_encrypt_functions.main(len(args), args)

   
   
    #cpabe-keygen -o sara_priv_key pub_key master_key test/policy

    #testing CP-ABE key generation algorithim
    print("\n\nTesting CP-ABE key generation ....")
    cpabe_keygen_functions = CDLL(cpabe_keygen_file)

    cpabe_keygen_functions.main.restype = c_int
    cpabe_keygen_functions.main.argtypes = c_int,POINTER(c_char_p)

    args = make_args('5 -o priv_key pub_key master_key foo')
    print(*args)
    cpabe_keygen_functions.main(len(args), args)


   
    #testing CP-ABE decrypt algorithim
    print("\n\nTesting CP-ABE decrypt ....")
    cpabe_decrypt_functions = CDLL(cpabe_dec_file)

    cpabe_decrypt_functions.main.restype = c_int
    cpabe_decrypt_functions.main.argtypes = c_int,POINTER(c_char_p)
    #cpabe-dec PUB_KEY PRIV_KEY FILE
    args = make_args('3 pub_key sara_priv_key flatten_sbom.cpabe')
    print(*args)
    cpabe_decrypt_functions.main(len(args), args)


   
if __name__ == "__main__":
    main()





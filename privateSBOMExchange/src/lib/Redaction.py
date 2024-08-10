from __future__ import print_function
import pyopenabe
from lib4sbom.parser import SBOMParser
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
import json


def addtoTree(tree,key,value):
    print(key,value)
    print(type(key), type(value))
    assert DEFAULTVALUE == tree.get(b"c")

    
    root1 = tree.update(key.encode("utf-8"), value.encode("utf-8"))
    assert 32 == len(root1)
    assert root1 != PLACEHOLDER
    

def prove(tree,key,value):
    proof = tree.prove(key)
    assert proof.sanity_check()
    assert verify_proof(proof,tree.root, key, value )

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

def SBOMAsTree(file):
    f = open(file)

    data = json.load(f)
    result = {}
    #parsed_data = parse_json(data,result,"")
    data=flatten_data(data)

    #print(parsed_data)
    tree = SparseMerkleTree()
   

    
    #for item in parsed_data:
    #    print (item , " ",parsed_data[item],"\n")

    for item in (data):
        #print(item, data[item])
        #SBOMField={item,data[item]}
        addtoTree(tree,item,data[item])
    return tree
def SetupCPABE():
    openabe = pyopenabe.PyOpenABE()
    cpabe = openabe.CreateABEContext("CP-ABE")
    cpabe.generateParams()
    return cpabe

def EncryptCPABE (plaintext,cpabe, accessPolicy):
    cipherText = cpabe.encrypt(accessPolicy, plaintext)
    print("ABE cipherText: ", len(cipherText))
    return cipherText

def DecryptCPABE (cpabe, cipherText,identity):    
    recoveredPlaintext = cpabe.decrypt(identity, cipherText)
    print("Plaintext: ", recoveredPlaintext)
    return recoveredPlaintext

def GenerateKeyCPABE(cpabe, attributes , identity):
    cpabe.keygen(attributes, identity)
    
def main():
    
    print("Representing SBOM as a Sparse Merkle Tree")
    tree=SBOMAsTree("/Users/emanabuishgair/research/Redactable SBOMs/test/data/SPDX/chronicle-sbom.spdx.json")
    SBOMField=tree.get(b"spdxVersion")
    print("Testing CP-ABE setup")
    cpabe=SetupCPABE()
    
    print("Testing CP-ABE Encrypt")
    accessPolicy="((one or two) and three)"
    plaintext = SBOMField
    cipherText=EncryptCPABE(plaintext,cpabe,accessPolicy)
    
    print("Testing CP-ABE GenerateKey")
    attributes= "|two|three|"
    identity= "alice"
    GenerateKeyCPABE(cpabe)

    print("Testing CP-ABE Decrypt")
    identity="alice"
    recoveredPlaintext=DecryptCPABE(cpabe, cipherText,identity)
    assert plaintext == recoveredPlaintext, "Didn't recover the message!"

    
    print("Testing key import")
    msk = cpabe.exportSecretParams()
    mpk = cpabe.exportPublicParams()
    uk = cpabe.exportUserKey("alice")

    cpabe2 = openabe.CreateABEContext("CP-ABE")

    cpabe2.importSecretParams(msk)
    cpabe2.importPublicParams(mpk)
    cpabe2.importUserKey("alice", uk)

    pt2 = cpabe2.decrypt("alice", cipherText)
    print("PT: ", pt2)
    assert plaintext == pt2, "Didn't recover the message!"


if __name__ == "__main__":
    main()





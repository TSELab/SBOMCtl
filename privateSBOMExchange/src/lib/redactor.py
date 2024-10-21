import argparse
import encodings
import glob
import json
import logging
from ssl import DER_cert_to_PEM_cert
import logging, sys
from click import Path

from license_expression import get_spdx_licensing
import  spdx_tools
from spdx_tools.spdx.model import (Checksum, ChecksumAlgorithm, File, 
                                   FileType, Relationship, RelationshipType)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.parser.json import json_parser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from spdx_tools.spdx.model import Document
from spdx_tools.spdx3.bump_from_spdx2 import spdx_document
import os

Users={}
def Redact(SBOMFile, roleHierarchy, currentRole) :
        logging.debug("Inside Redact")
        redactedSBOM=""
        filename=""
        print(SBOMFile)
        """
        for dirpath,_,filenames in os.walk(SBOM):
            for f in filenames:
                    
                filename= os.path.abspath(os.path.join(SBOM, f))
                print(filename)

        """
        # read in an SPDX document from a file
        #document=json_parser.parse_from_file("./RedactableSBOMs/data/SPDX/V2.3/SPDXJSONExample-v2.3.spdx.json")
        document=parse_file(SBOMFile, "utf-8")

        print(document.creation_info.spdx_version)
                
        document.packages[0].version=str(hash(document.packages[0].version))

        #print(dir(document))
        # change the document's name
        document.creation_info.name = document.creation_info.name+"_redacted"

        # define a file and a DESCRIBES relationship between the file and the document
        #checksum = Checksum(ChecksumAlgorithm.SHA1, "71c4025dd9897b364f3ebbb42c484ff43d00791c")
        """

        file = File(name="./fileName.py", spdx_id="SPDXRef-File1", checksums=[checksum], 
                    file_types=[FileType.TEXT], 
                    license_concluded=get_spdx_licensing().parse("MIT and GPL-2.0"),
                    license_comment="licenseComment", copyright_text="copyrightText")

        relationship = Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-File1")
        
        # add the file and the relationship to the document 
        # (note that we do not use "document.files.append(file)" as that would circumvent the type checking)
        document.files = document.files + [file]
        document.relationships = document.relationships + [relationship]
        """
        # validate the edited document and log the validation messages
        # (depending on your use case, you might also want to utilize the validation_message.context)
        validation_messages = validate_full_spdx_document(document)
        for validation_message in validation_messages:
            logging.warning(validation_message.validation_message)

        # if there are no validation messages, the document is valid 
        # and we can safely serialize it without validating again
        if not validation_messages:

            write_file(document, "newSBOM.json", validate=False)
        
        spdx_document.bump_spdx_document(document)

        return redactedSBOM

def  GenerateSBOM (artifact) :
    logging.debug("Inside GenerateSBOM")
    #return SBOM

def GetRole(key):

    if key in Users:
        return Users[key]
    return None
    
def EnrollRoles (cert):
    logging.debug("Inside EnrollRoles")
    currentRole=""
    public_key=cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    #TODO verify the key 
    #import pdb; pdb.set_trace()
    user = {
        "organizationName": cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value,
        "commonName": cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value,
        "key":public_key
            }
    Users[user["key"]] = user

    #print(cert.public_key())

    currentRole=GetRole(public_key)

    return currentRole["commonName"]
    
def CalculateRoles (policy):
    logging.debug("Inside CalculateRoles")
    rawFile = open(policy,"r",encoding="utf-8")
    
    data = json.load(rawFile)

    # print the keys and values
    for key in data:
        value = data[key]
        print("The key and value are ({}) = ({})".format(key, value))
        
    roleHierarchy=""

    return roleHierarchy
  





 

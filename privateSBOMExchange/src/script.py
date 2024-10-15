
import argparse
import sys
import os

from lib.redactor import *

import logging

def main():

    #print("Inside main")
    #logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    logging.debug('Inside main')

    parser = argparse.ArgumentParser()
    parser.add_argument('-certificate', help='Certificate file',required=True)
    parser.add_argument('-SBOM', help='SBOM file',required=True)
    parser.add_argument('-artifact', help='Artifact file',required=False)
    parser.add_argument('-policy', help='Policy file',required=False)

    args = parser.parse_args()
    #print (args.certificateFile)
    redacted_SBOM=Redact(args.SBOM,"roleHierarchy","currentRole")
    return
    f = open(args.certificate, "rb")
    
    cert=x509.load_der_x509_certificate(f.read())
    public_key=cert.public_key() 
    #print(public_key.public_bytes( ))

    #print("subject:: ",cert.subject)

    currentRole=EnrollRoles(cert)
    generatedSBOM=GenerateSBOM(args.artifact)
 
    roleHierarchy=CalculateRoles(args.policy)
    

if __name__ == "__main__":
    main()

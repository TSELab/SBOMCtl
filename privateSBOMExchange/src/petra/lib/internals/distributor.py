from cryptography import x509
from petra.lib.internals.common.common import verify_sbom_tree_signature

class Distributor:
    def __init__(self, redacted_sbom_tree, cert):
        self.redacted_sbom_tree = redacted_sbom_tree
        self.producer_cert = x509.load_pem_x509_certificate(cert.encode())
        if not verify_sbom_tree_signature(self.producer_cert, self.redacted_sbom_tree):
            raise Exception("Producer Signature verification failed")


        

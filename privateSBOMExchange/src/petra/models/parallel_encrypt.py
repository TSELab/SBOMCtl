from multiprocessing import Pool
from cpabe import cpabe_encrypt, cpabe_decrypt, ac17_cpabe_encrypt, ac17_cpabe_decrypt, cpabe_decrypt_many, cpabe_encrypt_many
import configparser
import os

from petra.lib.models import FieldNode, SbomNode, ComplexNode, NODE_REDACTED, NODE_PUBLIC

class ParallelEncryptVisitor:

    """Visitor that does a 'collect then encrypt parallely' process to
    increase performance"""
    def __init__(self, pk, decryptor="cpabe"):
        self.pk = pk
        self.workqueue = [] 
        if decryptor == "cpabe":
            self.target_func = cpabe_encrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_encrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def central_visit(self, node):
        if node.type == NODE_COMPLEX:
            self._visit_complex_node(node)
        elif node.type == NODE_SBOM:
            self._visit_sbom_node(node)
        elif node.type == NODE_FIELD:
            self._visit_field_node(node)

    def finalize(self):
        if len(self.workqueue) < 1:
            return
        policy = [x[2] for x in self.workqueue]
        plaintext = [x[3] for x in self.workqueue]
        pk = self.workqueue[0][1]
        nodes = [x[0] for x in self.workqueue] 
        #with Pool(processes=os.cpu_count()) as pool:
        #    result = pool.starmap(self.target_func, targets)
        result = cpabe_encrypt_many(pk, policy, plaintext)

        for node, encrypted_buffer in zip(nodes, result):
            node.encrypted_data = encrypted_buffer

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and encrypt its data using cpabe
        before encryption, the visitor fetch policy associated with node.field_name
        
        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.
        """
        data_to_encrypt = node.get_encryption_value()

        if node.policy != "" and data_to_encrypt:
            #print("data_to_encrypt: %s (total size= %s)" % (data_to_encrypt[32:].decode("utf-8"), str(len(data_to_encrypt))))
            
            # we append to the workqueue instead of actually encrypting
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt))

    def visit_complex_node(self, node:ComplexNode):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        data_to_encrypt =  node.get_encryption_value()

        if node.policy != "" and data_to_encrypt:
            # we append to the workqueue instead of actually encrypting
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt))

            #print(f"policy found for ComplexNode {node.complex_type} , {node.policy}")

        for child in node.children:
            child.accept(self)  # Visit each child

    def visit_sbom_node(self, node: SbomNode):
        """Visit an SbomNode and accept its children without encrypting."""
        print(f"Visiting SbomNode '{node.purl}', accepting children.")
        
        # Accept all child nodes without encryption
        for child in node.children:
            child.accept(self)

class ParallelDecryptVisitor:
    """A visitor that traverses nodes in the and decrypts encrypted data
    in each node using the provided secret key."""
    def __init__(self, secret_key, decryptor="cpabe"):
        # TODO: Get user's secret key from database
        self.secret_key = secret_key
        self.workqueue = []
        if decryptor == "cpabe":
            self.target_func = cpabe_decrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_decrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def finalize(self):
        if len(self.workqueue) < 1:
            return
        #targets = [(x[1], x[2]) for x in self.workqueue]
        sk = self.workqueue[0][1]
        targets = [ x[2] for x in self.workqueue]
        nodes = [x[0] for x in self.workqueue] 
        #with Pool(processes=os.cpu_count()) as pool:
        #    result = pool.starmap(self.target_func, targets)
        result = cpabe_decrypt_many(sk, targets)

        for node, decrypted_buffer in zip(nodes, result):
            # decrypted_data is stored as bytes now, cpabe_decrypt returns a list
            node.decrypted_data = bytes(decrypted_buffer)

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and decrypt its encrypted data using the secret key
        Parameters
        ----------
        node : FieldNode
            The field node whose ciphertext will be decrypted.
        """
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append((node, self.secret_key, node.encrypted_data))
        else:
            pass
            #print(f"No encrypted data found for FieldNode '{node.field_name}'.")

    def visit_complex_node(self, node:ComplexNode):  
        # Visit and decrypt all child nodes.
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append((node, self.secret_key, node.encrypted_data))

        for child in node.children:
            child.accept(self)  

    def visit_sbom_node(self, node: SbomNode): 
        # Visit and decrypt all child nodes.  
        for child in node.children:
            child.accept(self)

        del self.secret_key



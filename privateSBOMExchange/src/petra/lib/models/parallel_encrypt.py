from multiprocessing import Pool
from cpabe import cpabe_encrypt, cpabe_decrypt
import configparser
import os

from petra.lib.models import FieldNode, SbomNode, ComplexNode, NODE_REDACTED, NODE_PUBLIC

class ParallelEncryptVisitor:

    """Visitor that does a 'collect then encrypt parallely' process to
    increase performance"""
    def __init__(self, pk, policy_file):
        self.policy = self.load_policies(policy_file)
        self.pk = pk
        self.workqueue = [] 

    def central_visit(self, node):
        if node.type == NODE_COMPLEX:
            self._visit_complex_node(node)
        elif node.type == NODE_SBOM:
            self._visit_sbom_node(node)
        elif node.type == NODE_FIELD:
            self._visit_field_node(node)

    def finalize(self):
        targets = [(x[1], x[2], x[3]) for x in self.workqueue]
        nodes = [x[0] for x in self.workqueue] 
        with Pool(processes=os.cpu_count()) as pool:
            result = pool.starmap(cpabe_encrypt, targets)

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
        data_to_encrypt=f"{node.field_name}{node.field_value}"
        #if parent node(complex node) found policy for this node, encrypt the data using it and erase field node data
        if node.policy:
            print(f"policy found for FieldNode {node.field_name}, {node.policy}.")

            # we append to the workqueue instead of actually encrypting
            #node.encrypted_data = cpabe_encrypt(self.pk, node.policy, data_to_encrypt.encode("utf-8"))
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt.encode("utf-8")))
            node.field_name=NODE_REDACTED
            node.field_value=NODE_REDACTED

    def visit_complex_node(self, node:ComplexNode):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        data_to_encrypt=f"{node.complex_type}"
        # Check for * policy( all fields policy ) for the complex node
        apply_to_all_fields = self.get_policy_for_complex_node(node.complex_type,"*")
        # if there is a rule for the identifier field of the complexnode, and all fields rule , apply OR (attributes1 or attributes2) to the attributes

        # TODO this should find the specific children that the "placeholder" attribute identifies
        complex_node_identifier_policy_attributes=self.get_policy_for_complex_node(node.complex_type, "placeholder")
        
        if complex_node_identifier_policy_attributes and apply_to_all_fields:
            node.policy= "("+apply_to_all_fields + ") or ("+complex_node_identifier_policy_attributes+")"
        elif complex_node_identifier_policy_attributes:
            node.policy=complex_node_identifier_policy_attributes
        elif apply_to_all_fields:
            node.policy=apply_to_all_fields
        
        if node.policy:

            #node.encrypted_data = cpabe_encrypt(self.pk, node.policy,data_to_encrypt.encode("utf-8"))  
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt.encode("utf-8")))
            node.complex_type=NODE_REDACTED
            print(f"policy found for ComplexNode {node.complex_type} , {node.policy}")

        for child in node.children:
            if apply_to_all_fields:
                child.policy = apply_to_all_fields  # Set the  inherited policy
            else:
                child.policy = self.get_policy_for_field_node(node.complex_type,child.field_name) #set specific field policy
            child.accept(self)  # Visit each child

    def visit_sbom_node(self, node: SbomNode):
        """Visit an SbomNode and accept its children without encrypting."""
        print(f"Visiting SbomNode '{node.purl}', accepting children.")
        
        # Accept all child nodes without encryption
        for child in node.children:
            child.accept(self)

    # msm: i'm confused by the need to get the parent's policy, when the parent already has the child's
    def get_policy_for_field_node(self, parent_type, field_name):
        """Get the policy for a FieldNode based on its name and parent node type, case-insensitive."""
        field_name_lower = field_name.lower()
        parent_type_lower= parent_type.lower()
        
        # Check for specific field policies
        specific_policy = self.policy.get((parent_type_lower, field_name_lower))

        if specific_policy == None:
            return ""
        
        return specific_policy

    # msm: shouldn't to_redact_field be a list?
    def get_policy_for_complex_node(self, complex_node_type, to_redact_field):
        """Get the policy for a ComplexNode based on its metadata type name, case-insensitive."""
        return self.policy.get((complex_node_type.lower(), to_redact_field.lower()))
    
    def load_policies(self, policy_file):
        """Load policies from the given INI file into a dictionary, supporting general and specific cases."""
        config = configparser.ConfigParser()
        config.read(policy_file)
        policies = {}

        for section in config.sections():
            for option in config.options(section):
                policies[(section.lower(), option.lower())] = config.get(section, option)

        return policies


class ParallelDecryptVisitor:
    """A visitor that traverses nodes in the and decrypts encrypted data
    in each node using the provided secret key."""
    def __init__(self, secret_key):
        # TODO: Get user's secret key from database
        self.secret_key = secret_key
        self.workqueue = []

    def stringify(self, buffer):
        return [chr(x) for x in buffer]


    def finalize(self):
        targets = [(x[1], x[2]) for x in self.workqueue]
        nodes = [x[0] for x in self.workqueue] 
        with Pool(processes=os.cpu_count()) as pool:
            result = pool.starmap(cpabe_decrypt, targets)

        for node, decrypted_buffer in zip(nodes, result):
            node.decrypted_data = self.stringify(decrypted_buffer)



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
            print(f"No encrypted data found for FieldNode '{node.field_name}'.")

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



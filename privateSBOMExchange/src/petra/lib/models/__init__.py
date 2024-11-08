from __future__ import annotations

import configparser
from typing import List

from smt.tree import TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

import hashlib
from lib4sbom.parser import SBOMParser

from cpabe import cpabe_encrypt,cpabe_decrypt

# node markers
NODE_REDACTED="encrypted"
NODE_PUBLIC="public"

NODE_FIELD="F"
NODE_COMPLEX="C"
NODE_SBOM="S"


class Node:
    """Base class for a node in the SBOM tree."""

    def __init__(self):
        self.hash:bytes = None
    
    def accept(self, visitor):
        raise NotImplementedError("Must implement accept method.")


class FieldNode(Node):
    """Represents a field node that is a leaf in the tree, containing an SBOM field as a string.

    Attributes
    ----------
    field_name : str
        The field name stored as a string.
    field_value : str
        The field data stored as a string.
    encrypted_data : str
        The encrypted data using cpabe, initially set to placeholder value and might be set by EncryptVisitor based on the policy
    hash: bytes or None
        The hash of the data, initially set to None, should be set by the MerkleVisitor
    policy: str
        The policy associated with this field, might be set by EncryptVisitor based on the policy

    """
    def __init__(self, field:str, value:str):
        """Initialize a FieldNode.

        Parameters
        ----------
        field : str
            The field name.
        value : str
            The field value
        """
        self.field_name = field
        self.field_value = value
        self.plaintext_hash:bytes=hashlib.sha256((f"{field}{value}").encode()).digest()
        self.encrypted_data:str=NODE_PUBLIC
        self.decrypted_data:str=""
        self.policy:str=""

    def accept(self, visitor):
        return visitor.visit_field_node(self)

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to a JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_FIELD
        node_dict['name'] = self.field_name
        node_dict['value'] = self.field_value
        node_dict['plaintext_hash'] = self.plaintext_hash
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['decrypted_data'] = self.decrypted_data
        node_dict['policy'] = self.policy
        node_dict['hash'] = self.hash.hex()

        return node_dict

    @staticmethod
    def from_dict(node_dict: dict) -> FieldNode:
        """ Deserializes the node from a dict that came
            from JSON or other format.
        """
            
        if node_dict['t'] != NODE_FIELD:
            raise ValueError('Expected FieldNode type')
        
        n = FieldNode(node_dict['name'], node_dict['value'])
        n.hash = bytes.fromhex(node_dict['hash'])
        n.plaintext_hash = node_dict['plaintext_hash']
        n.encrypted_data = node_dict['encrypted_data']
        n.decrypted_data = node_dict['decrypted_data']
        n.policy = node_dict['policy']

        return n

class ComplexNode(Node):
    """Represents a complex node that can have multiple children of type FieldNode.

    Attributes
    ----------
    complex_type : str
        The type of the complex node, it can have one of these values: document information, package , vulnerability, file, service, license or relationship
    encrypted_data : str
        The encrypted data using cpabe, initially set to placeholder value and might be set by EncryptVisitor based on the policy
    children : List[FieldNode]
        A list of child FieldNode instances.
    """
    def __init__(self, complex_type:str, children:List[FieldNode]):
        """Initialize a ComplexNode.

        Parameters
        ----------
        node_type : str
            The type of the complex node.
        children : List[FieldNode]
            A list of FieldNode instances representing the fields of the package.
        """
        self.complex_type:str=complex_type
        self.plaintext_hash:bytes=hashlib.sha256((f"{complex_type}").encode()).digest()
        self.encrypted_data=NODE_PUBLIC
        self.decrypted_data:str=""
        self.children = children
        self.policy:str=""

    def accept(self, visitor):
        return visitor.visit_complex_node(self)

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to a JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_COMPLEX
        node_dict['type'] = self.complex_type
        node_dict['plaintext_hash'] = self.plaintext_hash
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['decrypted_data'] = self.decrypted_data
        node_dict['policy'] = self.policy
        node_dict['hash'] = self.hash.hex()

        children = dict()
        for c in self.children:
            children[c.hash.hex()[:7]] = c.to_dict()

        node_dict['children'] = children

        return node_dict

    @staticmethod
    def from_dict(node_dict: dict) -> ComplexNode:
        """ Deserializes the node from a dict that came from
        JSON or other format.
        """
        
        if node_dict['t'] != NODE_COMPLEX:
                raise ValueError("Expected ComplexNode type")

        children = list[Node]()
        for c, d in node_dict['children'].items():
            
            if d['t'] == NODE_FIELD:
                children.append(FieldNode.from_dict(d))
            else:
                raise ValueError('Expected FieldNode as child')
        
        n = ComplexNode(node_dict['type'], children)
        n.hash = bytes.fromhex(node_dict['hash'])
        n.plaintext_hash = node_dict['plaintext_hash']
        n.encrypted_data = node_dict['encrypted_data']
        n.decrypted_data = node_dict['decrypted_data']
        n.policy = node_dict['policy']

        return n

class SbomNode(Node):
    """Represents the root node of a Software Bill of Materials (SBOM) tree.

    This node can have two types of children, which are derived from the Node class:
    1. **ComplexNode**: Represents a complex node that has multiple children.
    2. **SbomNode**: Represents a package dependency that does have an available SBOM tree in the database.

    Attributes
    ----------
    hash: bytes or None
        The hash of the data, initially set to None, should be set by the MerkleVisitor
    children : List[Node]
        A list of child nodes, which can be FieldNode, PackageNode, or other SbomNode instances.
    signature : 
        signature over the hash, signed by the generator
    purl : str
        package url 
    """
    def __init__(self, purl:str, children:List[Node]):
        """Initialize an SbomNode.

        Parameters
        ----------
        purl : str
            package url for the sbom artifact
        children : List[Node]
            A list of child nodes that can be FieldNode, PackageNode, or other SbomNode instances.
        """
        self.purl:str=purl
        self.children = children
        self.signature=None

    def accept(self, visitor):
        # Accept the visitor on the root node and then on all children
        return visitor.visit_sbom_node(self)

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_SBOM
        node_dict['purl'] = self.purl
        node_dict['hash'] = self.hash.hex()

        if self.signature:
            node_dict['signature'] = self.signature.hex()
        else:
            node_dict['signature'] = ""

        children = dict()
        for c in self.children:
            children[c.hash.hex()[:7]] = c.to_dict()

        node_dict['children'] = children

        return node_dict

    @staticmethod
    def from_dict(node_dict: dict) -> SbomNode:
        """ Deserializes the node from a dict that came
            from JSON or other format.
        """
        if node_dict['t'] != NODE_SBOM:
            raise ValueError("Expected SbomNode type")

        children = list[Node]()
        for c, d in node_dict['children'].items():
            child = Node()
            
            if d['t'] == NODE_FIELD:
                child = FieldNode.from_dict(d)
                children.append()
            elif d['t'] == NODE_COMPLEX:
                child = ComplexNode.from_dict(d)
            else:
                child = SbomNode.from_dict(d)

            children.append(child)
        
        n = SbomNode(node_dict['purl'], children)
        n.hash = bytes.fromhex(node_dict['hash'])

        if node_dict['signature'] == "":
            n.signature = None
        else:
            n.signature = bytes.fromhex(node_dict['signature'])

        return n

    
class MerkleVisitor:
    """Visitor that computes the hash of the data in the nodes."""
    def visit_field_node(self, node:FieldNode):
        """Visit a FieldNode and compute the hash of its data.

        The hash is computed using the formula:
        if data is encrypted: H(node.encrypted_data|policy)
        If data is not encrypted: H(field_name|field_value|policy)

        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.

        Returns
        -------
        bytes
            The computed hash of the field node data.
        """
        if node.encrypted_data != NODE_PUBLIC:
            # we want to obscure this because a duplicated
            # NODE_REDACTED value will leak that it's a field node.
            # we could easily address this elsewhere too 
            data_to_hash=(f"{node.encrypted_data}{NODE_REDACTED}{node.policy}").encode()
        else:
            data_to_hash=(f"{node.encrypted_data}{node.field_name}{node.field_value}{node.policy}").encode()
        
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash 
    
    def visit_complex_node(self, node:ComplexNode):
        """Visit a ComplexNode and compute the hash of its data and children.

        The hash is computed using the formula:
        if data is encrypted:  H( node.encrypted_data | children )

        If data is not encrypted:
        H( node.encrypted_data | children )

        Parameters
        ----------
        node : ComplexNode
            The node whose data and children will be hashed.

        Returns
        -------
        bytes
            The computed hash of the complex node.
        """
        children_hashes = b''.join(child.accept(self) for child in node.children)
        
        data_to_hash=(f"{node.encrypted_data}{node.complex_type}{node.policy}").encode()+children_hashes
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash
    
    def visit_sbom_node(self, node:SbomNode):
        """Visit an SbomNode and compute the hash of its data and children.

        The hash is computed using the formula:
        H( (sbomName) | children)

        Parameters
        ----------
        node : SbomNode
            The SBOM node whose data and children will be hashed.

        Returns
        -------
        bytes
            The computed hash of the SBOM node data and its children.
        """
        children_hashes = b''.join(child.accept(self) for child in node.children)
        data_to_hash = (f"{node.purl}").encode() + children_hashes
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash 


class PrintVisitor:
    """Visitor that prints the data and hash of each node."""
    def visit_field_node(self, node:FieldNode):
        print(f"{node.encrypted_data};{node.field_name}:{node.field_value};{node.policy}")

        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            pass
            #print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

    def visit_complex_node(self, node:ComplexNode):
        print(f"{node.encrypted_data};{node.complex_type};{node.policy}") 
        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            pass
            #print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

        for child in node.children:
            child.accept(self)
            
    def visit_sbom_node(self, node:SbomNode):
        print(f"SBOM: {node.purl}") 
        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            pass
            #print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")
            
        for child in node.children:
            child.accept(self)        


class EncryptVisitor:
    """Visitor that encrypts the data in the nodes based on policies."""
    def __init__(self, pk, policy_file):
        self.policy = self.load_policies(policy_file)
        self.pk = pk

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
            node.encrypted_data = cpabe_encrypt(self.pk, node.policy, data_to_encrypt.encode("utf-8"))
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
            node.encrypted_data = cpabe_encrypt(self.pk, node.policy,data_to_encrypt.encode("utf-8"))  
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

class DecryptVisitor:
    """A visitor that traverses nodes in the and decrypts encrypted data
    in each node using the provided secret key."""
    def __init__(self, secret_key):
        # TODO: Get user's secret key from database
        self.secret_key = secret_key

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and decrypt its encrypted data using the secret key
        Parameters
        ----------
        node : FieldNode
            The field node whose ciphertext will be decrypted.
        """
        if node.encrypted_data != NODE_PUBLIC:
            try:
                node.decrypted_data =  "".join([chr(x) for x in cpabe_decrypt(self.secret_key, node.encrypted_data)])
            except Exception as e:
                print(f"Decryption failed with error: {e}")
        else:
            print(f"No encrypted data found for FieldNode '{node.field_name}'.")

    def visit_complex_node(self, node:ComplexNode):  
        # Visit and decrypt all child nodes.
        if node.encrypted_data != NODE_PUBLIC:
            node.decrypted_data =  "".join([chr(x) for x in cpabe_decrypt(self.secret_key, node.encrypted_data)])

        for child in node.children:
            child.accept(self)  

    def visit_sbom_node(self, node: SbomNode): 
        # Visit and decrypt all child nodes.  
        for child in node.children:
            child.accept(self)

        del self.secret_key

     
#represent SBOM in file as Merkle tree
def SBOM_as_tree(flatten_SBOM_data,sbom_file_encoding):
    tree = SparseMerkleTree(store=TreeMemoryStore())
    tree_name = ""
    
    # Add each SBOM field to the tree
    for field_name, value in flatten_SBOM_data.items():
        if field_name == "name":
            tree_name = value
        # Prepare the SBOM field for insertion
        sbom_field = {field_name: value}
        for item, item_value in sbom_field.items():
            # Convert boolean values to strings
            if isinstance(item_value, bool):
                item_value = str(item_value)
            try:
                # Update the tree and assert conditions
                root_after_update = tree.update(item.encode(sbom_file_encoding), item_value.encode(sbom_file_encoding))
                assert len(root_after_update) == 32, "Root after update must be 32 bytes."
                assert root_after_update != PLACEHOLDER, "Root cannot be a placeholder."
                assert DEFAULTVALUE == tree.get(b""), "Tree must return default value for an empty key."
            except Exception as e:
                print(f"Error updating tree with {item}: {e}")
    return tree, tree_name


def prove(tree, SBOMFields):
    """
    Generate and verify proofs for specified fields in a Sparse Merkle Tree.

    Parameters:
        tree (SparseMerkleTree): The Sparse Merkle Tree instance from which to generate proofs.
        SBOMFields (dict): A dictionary containing the SBOM fields and their corresponding values.

    Raises:
        AssertionError: If any proof fails the sanity check or verification.
        KeyError: If a field in SBOMFields is not found in the tree.
    """
    for item, expected_value in SBOMFields.items():
        try:
            proof = tree.prove(item)
            assert proof.sanity_check(), f"Sanity check failed for item: {item}"
            assert verify_proof(proof, tree.root, item, expected_value), f"Verification failed for item: {item}"
        except KeyError:
            print(f"Field '{item}' not found in the tree.")
        except Exception as e:
            print(f"An error occurred while processing '{item}': {e}")


def tree_from_nodes(nodes, values, root):
    """
    Create a SparseMerkleTree from given nodes, values, and root.

    Parameters:
        nodes (list): A list of nodes to be included in the tree.
        values (list): A list of values corresponding to each node.
        root (NodeType): The root node of the tree.

    Returns:
        SparseMerkleTree: An instance of SparseMerkleTree initialized with the provided nodes, values, and root.
    """
    # Create a new Sparse Merkle Tree instance
    new_tree = SparseMerkleTree(store=TreeMemoryStore())
    
    # Initialize memory store with nodes and values
    memorystore = TreeMemoryStore()
    memorystore.nodes = nodes
    memorystore.values = values

    # Set the memory store and root for the new tree
    new_tree.store = memorystore
    new_tree.root = root
    return new_tree


#this function is just to try things, should be replaced by the real cpabe
def cpabe(data):
    if not isinstance(data, bytes):
        return data.encode()
    else:
        return data

       
def build_sbom_tree(parser:SBOMParser):
    """Builds a SBOM tree from an SBOM.""" 
    leaves = []
    root_children = []

    #create internal node for document information
    document_info=parser.get_document()
    doc_fields: List[FieldNode] = [
    FieldNode(key,value)
    for key, value in document_info.items()
    if not key.startswith('_') # Exclude internal attributes
    ]
    root_children.append(ComplexNode("Document Information", doc_fields))
    
    # Create internal node for each package
    pkgs=parser.get_packages()
    if(pkgs):
        for package in pkgs:
            # Extract fields for each package
            package_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in package.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Package", package_fields))

    # Create internal node for each file
    files=parser.get_files()
    if(files):
        for file in files:
            # Extract fields for each file
            file_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in file.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("File", file_fields))
    
    # Create internal node for each license        
    licenses=parser.get_licenses()
    if (licenses):
        for license in licenses:
            # Extract fields for each license
            license_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in license.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("License", license_fields))

    # Create internal node for each vulnerability
    vulnerabilities=parser.get_vulnerabilities()
    if (vulnerabilities):
        for vulnerability in vulnerabilities:
            # Extract fields for each vulnarability
            vulnerability_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in vulnerability.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Vulnerability", vulnerability_fields))

    # Create internal node for each relationship
    relationships=parser.get_relationships()
    if (relationships):
        for relationship in relationships:
            # Extract fields for each relationship
            relationship_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in relationship.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Relationship", relationship_fields))

    # Create internal node for each service
    services=parser.get_services()
    if(services):
        for service in services:
            # Extract fields for each service
            service_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in service.items()
                if not key.startswith('_') # Exclude internal attributes
            
            ]
            root_children.append(ComplexNode("Service", service_fields))

    # TODO pass as purl in from somewhere else
    pURL=parser.get_document()["name"] # TODO this should become a field node under the SBOM node
    root = SbomNode(pURL, root_children)
    #ToDo store sign (root) , hash (root), and the tree in the database
    return root

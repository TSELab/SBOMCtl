import configparser
from typing import List
import re

from smt.tree import TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

import hashlib
from lib4sbom.parser import SBOMParser

from cpabe import cpabe_encrypt,cpabe_setup,cpabe_keygen,cpabe_decrypt

pk, mk = cpabe_setup()
GROUPS = ["FEDRAMP" , "COMPLIANCE"]
sk = cpabe_keygen(pk, mk, GROUPS)
"""            pt = cpabe_decrypt(sk, node.encrypted_data)
            pt_text = "".join([chr(x) for x in pt])
            assert pt_text == data_to_encrypt"""
class Node:
    """Base class for a node in the SBOM tree."""
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
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the data, initially set to None.
    """
    def __init__(self, field:str,value:str):
        self.field_name = field 
        self.field_value=value 
        self.encrypted_data=None #store encrypted data when visited by Encrypt visitor
        self.hash=None #store hashed data when visited by MerkleVisitor
        self.policy=None
    def accept(self, visitor):
        return visitor.visit_field_node(self)


class ComplexNode(Node):
    """Represents a package node that can have multiple children of type FieldNode.

    This node represents a dependency that does not have an available SBOM tree in the database.

    Attributes
    ----------
    field_name : str
        "PackageName".
    field_value :str
        The package name.
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the package data, initially set to None.
    children : List[FieldNode]
        A list of child FieldNode instances.
    """
    def __init__(self, type_name:str,type_value:str, children:List[FieldNode]):
        """Initialize a PackageNode.

        Parameters
        ----------
        package_name : str
            The name of the package.
        children : List[FieldNode]
            A list of FieldNode instances representing the fields of the package.
        """
        self.metadata_type_name:str= type_name  # Store data as string
        self.metadata_type_value:str=type_value
        self.encrypted_data=None #store encrypted data when visited by Encrypt visitor
        self.hash=None #store hashed data when visited by Merkle visitor
        self.children = children

    def accept(self, visitor):
        return visitor.visit_complex_node(self)


class SbomNode(Node):
    """Represents the root node of a Software Bill of Materials (SBOM) tree.

    This node can have three types of children, all of which are derived from the Node class:
    1. **FieldNode**: Represents a field in an SBOM document.
    2. **ComplexNode**: Represents a complex node that has multiple fields.
    3. **SbomNode**: Represents a package dependency that does have an available SBOM tree in the database.

    Attributes
    ----------
    SBOM_name : str
        The name or identifier of the SBOM.
    encrypted_data : bytes or None
        The encrypted verison of the data, initially set to None.
    hash : bytes or None
        The hashed version of the data, initially set to None.
    children : List[Node]
        A list of child nodes, which can be FieldNode, PackageNode, or other SbomNode instances.
    """
    def __init__(self,name:str,purl, children:List[Node]):
        """Initialize an SbomNode.

        Parameters
        ----------
        name : str
            The name of the SBOM.
        children : List[Node]
            A list of child nodes that can be FieldNode, PackageNode, or other SbomNode instances.
        """
        self.SBOM_name=name
        self.encrypted_data=None #store encrypted data when visited by Encrypt visitor
        self.hash=None #store hashed data when visited by Merkle visitor
        self.children = children  # Hold the children directly
        self.signiture=None
        self.pURL=purl
    def accept(self, visitor):
        # Accept the visitor on the root node and then on all children
        return visitor.visit_sbom_node(self)

  
class MerkleVisitor:
    """Visitor that computes the hash of the data in the nodes."""
    def visit_field_node(self, node:FieldNode):
        """Visit a FieldNode and compute the hash of its data.

        The hash is computed using the formula:
        if data is encrypted: H(node.encrypted_data)
        If data is not encrypted: H("Field"|field_name|field_value)

        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.

        Returns
        -------
        bytes
            The computed hash of the field node data.
        """
        if node.encrypted_data is not None:
            data_to_hash= node.encrypted_data
        else:
            data_to_hash=(f"Field{node.field_name}{node.field_value}").encode()
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash # Return the hash as bytes
    
    def visit_complex_node(self, node:ComplexNode):
        """Visit a ComplexNode and compute the hash of its data and children.

        The hash is computed using the formula:
        if data is encrypted:  H(node.encrypted_data) | children)

        If data is not encrypted:
        H(node.encrypted_data) | children)

        Parameters
        ----------
        node : ComplexNode
            The node whose data and children will be hashed.

        Returns
        -------
        bytes
            The computed hash of the complex node data and its children.
        """
        # get hashes of the children
        children_hashes = b''.join(child.accept(self) for child in node.children)
        if node.encrypted_data is not None:
            data_to_hash = node.encrypted_data+children_hashes
        else:
            data_to_hash=(node.metadata_type_name +node.metadata_type_value).encode()+children_hashes
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
        # Compute hash for the root using its data and the hashes of its children

        children_hashes = b''.join(child.accept(self) for child in node.children)
        data_to_hash = (node.SBOM_name).encode() + children_hashes
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash 


class PrintVisitor:
    """Visitor that prints the data and hash of each node."""
    def visit_field_node(self, node:FieldNode):
        print(f"Field:{node.field_name}:{node.field_value}")
        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

    def visit_complex_node(self, node:ComplexNode):
        print(f"{node.metadata_type_name}:{node.metadata_type_value}") 
        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

        for child in node.children:
            child.accept(self)
            
    def visit_sbom_node(self, node:SbomNode):
        print(f"SBOM: {node.SBOM_name}") 
        try:
            print(f"Hash: {node.hash.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")
        for child in node.children:
            child.accept(self)        


class EncryptVisitor:
    """Visitor that encrypts the data in the nodes based on policies."""
    
    def __init__(self, policy_file):
        self.policies = self.load_policies(policy_file)

    def visit_field_node(self, node: FieldNode):
        """Encrypt the data in a FieldNode."""
        data_to_encrypt=f"Field{node.field_name}{node.field_value}"
        #this handle flat fields node that doesnt have complex node as a parent these are document related information
        if(not node.policy):
            node.policy = self.get_policy_for_field_node("others",node.field_name)
        #if parent node(complex node) found policy for this node, encrypt the data using it and erase field node data
        if node.policy:
            print(f"policy found for FieldNode '{node.field_name}', {node.policy}.")
            node.encrypted_data = cpabe_encrypt(pk, node.policy, data_to_encrypt.encode("utf-8"))
            node.field_name=None
            node.field_value=None
        else:
            print(f"No policy found for FieldNode '{node.field_name}'.")

    def visit_complex_node(self, node):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        # Check for * policy() all fields policy) for the complex node
        apply_to_all_fields = self.get_policy_for_complex_node(node.metadata_type_name)
        
        for child in node.children:
            if apply_to_all_fields:
                child.policy = apply_to_all_fields  # Set the  inherited policy
            else:
                child.policy = self.get_policy_for_field_node(node.metadata_type_name,child.field_name.lower()) #set specific field policy
            child.accept(self)  # Visit each child
    
    def visit_sbom_node(self, node: SbomNode):
        """Visit an SbomNode and accept its children without encrypting."""
        print(f"Visiting SbomNode '{node.SBOM_name}', accepting children.")
        
        # Accept all child nodes without encryption
        for child in node.children:
            child.accept(self)

    def get_policy_for_field_node(self, parent_type,field_name):
        """Get the policy for a FieldNode based on its name, case-insensitive."""
        field_name_lower = field_name.lower()
        parent_type_lower= parent_type.lower()
        
        # Check for specific field policies
        specific_policy = self.policies.get((parent_type_lower, field_name_lower))
        return specific_policy

    def get_policy_for_complex_node(self, metadata_type_name):
        """Get the policy for a ComplexNode based on its metadata type name, case-insensitive."""
        # For the purpose of this example, assuming similar logic applies
        # You can extend this to handle different categories as needed
        return self.policies.get((metadata_type_name.lower(), '*'))
    
    def load_policies(self, policy_file):
        """Load policies from the given INI file into a dictionary, supporting general and specific cases."""
        config = configparser.ConfigParser()
        config.read(policy_file)
        policies = {}

        for section in config.sections():
            for option in config.options(section):
                policies[(section, option)] = config.get(section, option)

        return policies
    
     
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

       
def build_sbom_tree(doc:SBOMParser):
    """Builds a SBOM tree from an SBOM.""" 
    leaves = []
    #create internal nodes for each field
    document_info=doc.get_document()
    for field_name, field_value in document_info.items():
#        print(f"Field{field_name}{field_value}")
        if not field_name.startswith('_'):
            leaves.append(FieldNode(field_name,field_value))

    # Create internal nodes for each package
    pkgs=doc.get_packages()
    root_children = []

    for package in pkgs:
        # Extract fields for each package
        package_fields: List[FieldNode] = [
            FieldNode(key,value)
            for key, value in package.items()
            if not key.startswith('_')  # Exclude internal attributes 
        ]
        root_children.append(ComplexNode("Package",package["name"], package_fields))

    files=doc.get_files()
    if(files):
        for file in files:
            # Extract fields for each file
            file_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in file.items()
                if not key.startswith('_')  # Exclude internal attributes
            ]
            root_children.append(ComplexNode("File",file["name"], file_fields))
        
    licenses=doc.get_licenses()
    if (licenses):
        for license in licenses:
            # Extract fields for each license
            license_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in license.items()
                if not key.startswith('_')   # Exclude internal attributes
            ]
            root_children.append(ComplexNode("License",license["name"], license_fields))

    vulnarabilities=doc.get_vulnerabilities()
    if (vulnarabilities):
        for vulnarability in vulnarabilities:
            # Extract fields for each vulnarability
            vulnarability_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in vulnarability.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Vulnarability",vulnarability["product"], vulnarability_fields))

    relationships=doc.get_relationships()
    if (relationships):
        for relationship in relationships:
            # Extract fields for each relationship
            relationship_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in relationship.items()
                if not key.startswith('_')  # Exclude internal attributes 
            ]
            root_children.append(ComplexNode("Relationship",relationship["type"], relationship_fields))

    services=doc.get_services()
    if(services):
        for service in services:
            # Extract fields for each service
            service_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in service.items()
                if not key.startswith('_')  # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Service",service["name"], service_fields))

    sbom_name=doc.get_document()["name"]
    pURL=""
    root = SbomNode(sbom_name,pURL,leaves + root_children)
    #ToDo store sign (root) , hash (root), and the tree in the database
    return root

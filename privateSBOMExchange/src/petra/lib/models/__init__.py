import configparser
from typing import List
import re

import hashlib
from lib4sbom.parser import SBOMParser

from petra.lib.sbom.spdx import load_json_spdx
from cpabe import cpabe_encrypt,cpabe_setup,cpabe_keygen,cpabe_decrypt

from .sbom_tree import ComplexNode, FieldNode, SbomNode

pk, mk = cpabe_setup()
"""            pt = cpabe_decrypt(sk, node.encrypted_data)
            pt_text = "".join([chr(x) for x in pt])
            assert pt_text == data_to_encrypt"""

  
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
        if not isinstance(data_to_hash, bytes):
            data_to_hash=data_to_hash.encode()
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
        children_hashes = b''.join(child.accept(self) for child in node.children)
        data_to_hash = (node.SBOM_name).encode() + children_hashes
        node.hash=hashlib.sha256(data_to_hash).digest()
        return node.hash 



class EncryptVisitor:
    """Visitor that encrypts the data in the nodes based on policies."""
    def __init__(self, policy_file):
        self.policies = self.load_policies(policy_file)

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and encrypt its data using cpabe
        before encryption, the visitor fetch policy associated with node.field_name
        
        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.
        """
        data_to_encrypt=f"Field{node.field_name}{node.field_value}"
        #this handle flat fields node that doesnt have complex node as a parent these are document related information
        if(not node.policy):
            node.policy = self.get_policy_for_field_node("others",node.field_name)
        #if parent node(complex node) found policy for this node, encrypt the data using it and erase field node data
        if node.policy:
            print(f"policy found for FieldNode '{node.field_name}', {node.policy}.")
            node.encrypted_data = cpabe_encrypt(pk, node.policy, data_to_encrypt.encode("utf-8"))
            node.field_name=""
            node.field_value=""
        else:
            print(f"No policy found for FieldNode '{node.field_name}'.")

    def visit_complex_node(self, node:ComplexNode):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        # Check for * policy( all fields policy ) for the complex node
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
        """Get the policy for a FieldNode based on its name and parent node type, case-insensitive."""
        field_name_lower = field_name.lower()
        parent_type_lower= parent_type.lower()
        
        # Check for specific field policies
        specific_policy = self.policies.get((parent_type_lower, field_name_lower))
        return specific_policy

    def get_policy_for_complex_node(self, metadata_type_name):
        """Get the policy for a ComplexNode based on its metadata type name, case-insensitive."""
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

   
def recurse_into_sbom_subtree(target, key=None):

    # we may for some reason end up without a key
    # this would break our scheme in the complex node case
    # so we fail if that's the case.
    if not key and key != "":
        raise Exception("I failed trying to parse {}".format(target))

    # we should probably work on a tuple too...
    if type(target) == dict:
        thisnode = ComplexNode(key, [])

        for key in target:
            child = recurse_into_sbom_subtree(target[key], key)
            thisnode.children.append(child)

    elif type(target) == list:
        thisnode = ComplexNode(key, [])

        for value in target:
            child = recurse_into_sbom_subtree(value, "")
            thisnode.children.append(child)
    else: # basecase
        thisnode = FieldNode(key, target)

    return thisnode

def build_sbom_tree_from_file(filename:str, _format:str="spdx:json"):

    SUPPORTED_FORMATS = {
        "spdx:json": load_json_spdx
    }

    if _format not in SUPPORTED_FORMATS:
        raise Exception(f"Format {_format} is not supported, supported formats:\n{SUPPORTED_FORMATS}")


    target = SUPPORTED_FORMATS[_format](filename)

    root = SbomNode(target['name'], None, [])

    for key in target:
        if key == 'name':
            continue
        node = recurse_into_sbom_subtree(target[key], key)
        root.children.append(node)
   
    return root

def build_sbom_tree(parser:SBOMParser):
    """Builds a SBOM tree from an SBOM.""" 
    leaves = []
    #create internal nodes for each field
    document_info=parser.get_document()
    for field_name, field_value in document_info.items():
#        print(f"Field{field_name}{field_value}")
        if not field_name.startswith('_'):
            leaves.append(FieldNode(field_name,field_value))

    # Create internal nodes for each package
    pkgs=parser.get_packages()
    root_children = []

    for package in pkgs:
        # Extract fields for each package
        package_fields: List[FieldNode] = [
            FieldNode(key,value)
            for key, value in package.items()
            if not key.startswith('_')  # Exclude internal attributes 
        ]
        root_children.append(ComplexNode("Package",package["name"], package_fields))

    files=parser.get_files()
    if(files):
        for file in files:
            # Extract fields for each file
            file_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in file.items()
                if not key.startswith('_')  # Exclude internal attributes
            ]
            root_children.append(ComplexNode("File",file["name"], file_fields))
        
    licenses=parser.get_licenses()
    if (licenses):
        for license in licenses:
            # Extract fields for each license
            license_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in license.items()
                if not key.startswith('_')   # Exclude internal attributes
            ]
            root_children.append(ComplexNode("License",license["name"], license_fields))

    vulnerabilities=parser.get_vulnerabilities()
    if (vulnerabilities):
        for vulnerability in vulnerabilities:
            # Extract fields for each vulnarability
            vulnerability_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in vulnerability.items()
                if not key.startswith('_') # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Vulnerability",vulnerability["product"], vulnerability_fields))

    relationships=parser.get_relationships()
    if (relationships):
        for relationship in relationships:
            # Extract fields for each relationship
            relationship_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in relationship.items()
                if not key.startswith('_')  # Exclude internal attributes 
            ]
            root_children.append(ComplexNode("Relationship",relationship["type"], relationship_fields))

    services=parser.get_services()
    if(services):
        for service in services:
            # Extract fields for each service
            service_fields: List[FieldNode] = [
                FieldNode(key,value)
                for key, value in service.items()
                if not key.startswith('_')  # Exclude internal attributes
            ]
            root_children.append(ComplexNode("Service",service["name"], service_fields))

    sbom_name=parser.get_document()["name"]
    pURL=""
    root = SbomNode(sbom_name,pURL,leaves + root_children)
    #ToDo store sign (root) , hash (root), and the tree in the database
    return root

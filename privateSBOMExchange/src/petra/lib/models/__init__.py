from typing import List

from smt.tree import TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

import hashlib
from lib4sbom.parser import SBOMParser
       
class Node:
    """Base class for a node in the SBOM tree."""
    def accept(self, visitor):
        raise NotImplementedError("Must implement accept method.")


class FieldNode(Node):
    """Represents a field node that is a leaf in the tree, containing an SBOM field as a string.

    Attributes
    ----------
    data : str
        The field data stored as a string.
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the data, initially set to None.
    """
    def __init__(self, data:str):
        self.data = data  # Store data as string
        self.encrypted_and_hashed_data=None #store hashed data when visited by MerkleVisitor

    def accept(self, visitor):
        return visitor.visit_field_node(self)


class PackageNode(Node):
    """Represents a package node that can have multiple children of type FieldNode.

    This node represents a dependency that does not have an available SBOM tree in the database.

    Attributes
    ----------
    data : str
        The package name stored as data.
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the package data, initially set to None.
    children : List[FieldNode]
        A list of child FieldNode instances.
    """
    def __init__(self, package_name, children:List[FieldNode]):
        """Initialize a PackageNode.

        Parameters
        ----------
        package_name : str
            The name of the package.
        children : List[FieldNode]
            A list of FieldNode instances representing the fields of the package.
        """
        self.data = package_name  # Store package name as data
        self.encrypted_and_hashed_data=None
        self.children = children

    def accept(self, visitor):
        return visitor.visit_package_node(self)


class SbomNode(Node):
    """Represents the root node of a Software Bill of Materials (SBOM) tree.

    This node can have three types of children, all of which are derived from the Node class:
    1. **FieldNode**: Represents a field in an SBOM document.
    2. **PackageNode**: Represents a package dependency that does not have an available SBOM tree in the database.
    3. **SbomNode**: Represents a package dependency that does have an available SBOM tree in the database.

    Attributes
    ----------
    data : str
        The name or identifier of the SBOM.
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the data, initially set to None.
    children : List[Node]
        A list of child nodes, which can be FieldNode, PackageNode, or other SbomNode instances.
    """
    def __init__(self,data, children:List[Node]):
        """Initialize an SbomNode.

        Parameters
        ----------
        data : str
            The name of the SBOM.
        children : List[Node]
            A list of child nodes that can be FieldNode, PackageNode, or other SbomNode instances.
        """
        self.data=data
        self.encrypted_and_hashed_data=None
        self.children = children  # Hold the children directly

    def accept(self, visitor):
        # Accept the visitor on the root node and then on all children
        return visitor.visit_sbom_node(self)

  
class MerkleVisitor:
    """Visitor that encrypts then computes the hash of the data in the nodes."""
    def visit_field_node(self, node:FieldNode):
        """Visit a FieldNode and compute the hash of its data.

        The hash is computed using the formula:
        H(cpabe("Field" | Field Name | Field Value))
        where `cpabe` is the encryption technique used.

        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.

        Returns
        -------
        bytes
            The computed hash of the field node data.
        """
        leaf_data=f"Field{node.data}" # Format Field|{Field Name}|{Field Value}
        processed_data = cpabe(leaf_data) 
        hashed_data=hashlib.sha256(processed_data).digest()
        node.encrypted_and_hashed_data=hashed_data
        return hashed_data # Return the hash as bytes
    
    def visit_package_node(self, node:PackageNode):
        """Visit a PackageNode and compute the hash of its data and children.

        The hash is computed using the formula:
        H(cpabe("PackageName") | cpabe({PackageName}) | children)
        where `cpabe` is the encryption technique used.

        Parameters
        ----------
        node : PackageNode
            The package node whose data and children will be hashed.

        Returns
        -------
        bytes
            The computed hash of the package node data and its children.
        """
        encrypted_package = cpabe("PackageName")
        encrypted_package_name = cpabe(node.data)
        # get hashes of the children
        children_hashes = b''.join(child.accept(self) for child in node.children)
        data_to_hash = encrypted_package+encrypted_package_name+children_hashes
        hashed_data=hashlib.sha256(data_to_hash).digest()
        node.encrypted_and_hashed_data=hashed_data
        return hashed_data
    
    def visit_sbom_node(self, node:SbomNode):
        """Visit an SbomNode and compute the hash of its data and children.

        The hash is computed using the formula:
        H(cpabe(sbomName) | children)
        where `cpabe` is the encryption technique used.

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
        #ToDo if child is a root, dont accept it , just return its tree 
        children_hashes = b''.join(child.accept(self) for child in node.children)
        combined_data = cpabe(node.data) + children_hashes
        hashed_data=hashlib.sha256(cpabe(combined_data)).digest()
        node.encrypted_and_hashed_data=hashed_data
        return hashed_data 


class PrintVisitor:
    """Visitor that prints the data and hash of each node."""
    def visit_field_node(self, node:FieldNode):
        print(f"Field: {node.data}")
        try:
            print(f"Hash: {node.encrypted_and_hashed_data.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

    def visit_package_node(self, node:PackageNode):
        print(f"Package: {node.data}")  # Print package data
        try:
            print(f"Hash: {node.encrypted_and_hashed_data.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")

        for child in node.children:
            child.accept(self)
            
    def visit_sbom_node(self, node:SbomNode):
        print(f"SBOM: {node.data}")  # Print root data
        try:
            print(f"Hash: {node.encrypted_and_hashed_data.hex()}")
        except AttributeError:
            print("Hashes have not been calculated, you need to first visit the tree using the Merkle Visitor")
        for child in node.children:
            child.accept(self)        
     
     
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
    """Builds a Merkle tree from an SPDX SBOM.""" 
    leaves = []
    #create internal nodes for each field
    document_info=doc.get_document()
    for field_name, field_value in document_info.items():
#        print(f"Field{field_name}{field_value}")
        if not field_name.startswith('_'):
            leaves.append(FieldNode(f"{field_name}{field_value}"))

    # Create internal nodes for each package
    pkgs=doc.get_packages()
    root_children = []

    for package in pkgs:
        pkg_nodes=[]
        # Extract fields for each package
        package_fields = [
            
            FieldNode(f"{key}{value}")
            for key, value in package.items()
            if not key.startswith('_')  # Exclude internal attributes
        ]
        root_children.append(PackageNode(package["name"], package_fields))

    files=doc.get_files()
    if (files):
        for file in files:
            leaves.append(FieldNode(f"file{file}"))
        
    licenses=doc.get_licenses()
    if (licenses):
        for license in licenses:
            leaves.append(FieldNode(f"license{license}"))
        
    vulnarabilities=doc.get_vulnerabilities()
    if (vulnarabilities):
        for vulnarability in vulnarabilities:
            leaves.append(FieldNode(f"vulnarability{vulnarability}"))
            
    relationships=doc.get_relationships()
    if (relationships):
        for relationship in relationships:
            leaves.append(FieldNode(f"relationship{relationship}"))
          
    services=doc.get_services()
    if(services):
        for service in services:
            leaves.append(FieldNode(f"service{service}"))
    

    sbom_name=doc.get_document()["name"]

    root = SbomNode(sbom_name,leaves + root_children)
    #ToDo store sign (root) , hash (root), and the tree in the database
    return root

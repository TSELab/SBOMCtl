from __future__ import annotations

from typing import List

from smt.tree import TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

import hashlib
from lib4sbom.parser import SBOMParser

from cpabe import cpabe_encrypt,cpabe_decrypt

from petra.lib.models.policy import PetraPolicy

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
    def __init__(self, field:str, value:str, policy:str):
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
        self.plaintext_hash:bytes=hashlib.sha256((f"{field}:{value}").encode()).digest()
        self.encrypted_data:str=NODE_PUBLIC
        self.decrypted_data:str=""
        self.policy:str=policy
        self.hash:bytes = None

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
        node_dict['plaintext_hash'] = self.plaintext_hash.hex()
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['decrypted_data'] = self.decrypted_data
        node_dict['policy'] = self.policy

        if self.hash:
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
    def __init__(self, complex_type:str, policy:str, children:List[FieldNode]):
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
        self.policy:str=policy
        self.hash:bytes = None

    def accept(self, visitor):
        return visitor.visit_complex_node(self)

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to a JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_COMPLEX
        node_dict['type'] = self.complex_type
        node_dict['plaintext_hash'] = self.plaintext_hash.hex()
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['decrypted_data'] = self.decrypted_data
        node_dict['policy'] = self.policy

        if self.hash:
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
    def __init__(self, purl:str, children:List[Node], redaction_policy:dict=None):
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
        self.hash:bytes = None
        self.policy = redaction_policy

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

        if self.hash:
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
    def __init__(self, pk):
        self.pk = pk

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and encrypt its data using cpabe
        before encryption, the visitor fetch policy associated with node.field_name
        
        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.
        """
        data_to_encrypt=f"{node.field_name}:{node.field_value}"
        #if parent node(complex node) found policy for this node, encrypt the data using it and erase field node data
        if node.policy != "":
            #print(f"policy found for FieldNode {node.field_name}, {node.policy}.")
            node.encrypted_data = cpabe_encrypt(self.pk, node.policy, data_to_encrypt.encode("utf-8"))
            node.field_name=NODE_REDACTED
            node.field_value=NODE_REDACTED

    def visit_complex_node(self, node:ComplexNode):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        data_to_encrypt=f"{node.complex_type}"

        if node.policy != "":
            node.encrypted_data = cpabe_encrypt(self.pk, node.policy, data_to_encrypt.encode("utf-8"))  
            node.complex_type=NODE_REDACTED

        for child in node.children:        
            child.accept(self)  # Visit each child

    def visit_sbom_node(self, node: SbomNode):
        """Visit an SbomNode and accept its children without encrypting."""
        #print(f"Visiting SbomNode '{node.purl}', accepting children.")
        
        # Accept all child nodes without encryption
        for child in node.children:
            child.accept(self)

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
            pass
            #print(f"No encrypted data found for FieldNode '{node.field_name}'.")

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

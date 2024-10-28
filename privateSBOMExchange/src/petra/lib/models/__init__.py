from smt.tree import TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

import hashlib
from lib4sbom.parser import SBOMParser
       
class Node:
    """Base class for a node in the Merkle tree."""
    def accept(self, visitor):
        raise NotImplementedError("Must implement accept method.")


class Leaf(Node):
    """Represents a leaf node containing binary data."""
    def __init__(self, data):
        self.data = data  # Store data as bytes

    def accept(self, visitor):
        return visitor.visit_leaf(self)


class InternalNode(Node):
    """Represents an internal node that can have multiple children."""
    def __init__(self, package_name, children):
        self.data = package_name  # Store package name as data
        self.children = children

    def accept(self, visitor):
        return visitor.visit_internal_node(self)


class RootNode(Node):
    """Represents the root node of the Merkle tree, which can hold multiple internal nodes."""
    def __init__(self,data, children):
        self.children = children  # Hold the children directly
        self.data=data

    def accept(self, visitor):
        # Accept the visitor on the root node and then on all children
        return visitor.visit_root(self)

  
class MerkleVisitor:
    """Visitor that computes the hash of the nodes."""
    def visit_leaf(self, leaf):
        processed_data = cpabe(leaf.data)  # Process the leaf data
        return hashlib.sha256(processed_data).digest()  # Return the hash as bytes
    
    def visit_internal_node(self, node):
        #H(cpabe("PackageName") | cpabe(PackageName) | children)
        # Hash for field name: PackageName and field value: node.data
        encrypted_package = cpabe("PackageName")
        encrypted_package_name = cpabe(node.data)
        # get hashes of the children
        children_hashes = b''.join(child.accept(self) for child in node.children)
        data_to_hash = encrypted_package+encrypted_package_name+children_hashes
        return hashlib.sha256(data_to_hash).digest()
    
    def visit_root(self, root):
        # Compute hash for the root using its data and the hashes of its children
        children_hashes = b''.join(child.accept(self) for child in root.children)
        combined_data = root.data.encode() + children_hashes
        return hashlib.sha256(cpabe(combined_data)).digest()


class PrintVisitor:
    """Visitor that prints the data of each node."""
    def visit_leaf(self, leaf):
        print(f"Leaf: {leaf.data}")

    def visit_internal_node(self, node):
        print(f"Internal Node: {node.data}")  # Print package data
        for child in node.children:
            child.accept(self)
            
    def visit_root(self, root):
        print(f"Root: {root.data}")  # Print root data
        for child in root.children:
            child.accept(self)        
     
     
#represent SBOM in file as Merkle tree
def SBOM_as_tree(flatten_SBOM_data,sbom_file_encoding):
    tree = SparseMerkleTree(store=TreeMemoryStore())
    tree_name=""
    count=0
    # add each SBOM field to the tree
    for field_name,value in flatten_SBOM_data.items():
        count+=1
        SBOMField={field_name:value}
        if field_name =="name":
            tree_name=value
        assert DEFAULTVALUE == tree.get(b"")
        for item in SBOMField:
            if isinstance(SBOMField[item], bool):
                SBOMField[item]=str(SBOMField[item])
            root1 = tree.update(item.encode(sbom_file_encoding), SBOMField[item].encode(sbom_file_encoding))
            assert 32 == len(root1)
            assert root1 != PLACEHOLDER       
    return tree, tree_name


def try_tree():
    t=SparseMerkleTree(store=TreeMemoryStore())
    roota= t.update(b"a",b"a1")
    assert 32 == len(roota)
    assert roota !=PLACEHOLDER
    assert t.update(b"b",b"b2")
    assert DEFAULTVALUE == t.get(b"d")
    assert b"b2"== t.get(b"b")
    proof = t.prove(b"b")
    assert verify_proof(proof, t.root, b"b", b"b2")

    return t


def prove(tree, SBOMField):
    for item in SBOMField:
        proof = tree.prove(item)
        assert proof.sanity_check()
        assert verify_proof(proof,tree.root, item, SBOMField[item] )


def tree_from_nodes(nodes, values, root):    
    new_tree = SparseMerkleTree(store=TreeMemoryStore())
    memorystore=TreeMemoryStore()
    memorystore.nodes=nodes
    memorystore.values=values
    new_tree.store=memorystore
    new_tree.root=root
    return new_tree


#this function is just to try things, should be replaced by the real cpabe
def cpabe(data):
    if not isinstance(data, bytes):
        return data.encode()
    else:
        return data

       
def build_sbom_tree(doc):
    """Builds a Merkle tree from an SPDX SBOM.""" 
    leaves = []
    #create internal nodes for each field
    document_info=doc.get_document()
    for field_name, field_value in document_info.items():
#        print(f"Field{field_name}{field_value}")
        if not field_name.startswith('_'):
            leaves.append(Leaf(f"Field{field_name}{field_value}"))

    # Create internal nodes for each package
    pkgs=doc.get_packages()
    root_children = []

    for package in pkgs:
        pkg_nodes=[]
        # Extract fields for each package
        package_fields = [
            
            Leaf(f"Field{key}{value}")
            for key, value in package.items()
            if not key.startswith('_')  # Exclude internal attributes
        ]
        root_children.append(InternalNode(package["name"], package_fields))

    files=doc.get_files()
    if (files):
        for file in files:
            leaves.append(Leaf(f"Fieldfile{file}"))
        
    licenses=doc.get_licenses()
    if (licenses):
        for license in licenses:
            leaves.append(Leaf(f"Fieldlicense{license}"))
        
    vulnarabilities=doc.get_vulnerabilities()
    if (vulnarabilities):
        for vulnarability in vulnarabilities:
            leaves.append(Leaf(f"Fieldvulnarability{vulnarability}"))
            
    relationships=doc.get_relationships()
    if (relationships):
        for relationship in relationships:
            leaves.append(Leaf(f"Fieldrelationship{relationship}"))
          
    services=doc.get_services()
    if(services):
        for service in services:
            leaves.append(Leaf(f"Fieldservice{service}"))
                 
    # Create the root node containing all leaves and package nodes
    sbom_name=doc.get_document()["name"]
    root = RootNode(sbom_name,leaves + root_children)
    return root


# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file("../sbom_data/bom-shelter/in-the-wild/spdx/julia.spdx.json")   
# Build the tree and compute the root hash
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom)
print_visitor = PrintVisitor()
sbom_tree.accept(print_visitor)
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)
# Convert the root hash to a hexadecimal representation for display
merkle_root_hash_hex = merkle_root_hash.hex()
print("Merkle Root Hash for SBOM:", merkle_root_hash_hex)
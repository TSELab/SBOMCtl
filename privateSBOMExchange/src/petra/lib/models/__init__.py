from smt.tree import TreeMapStore, TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

from typing import Tuple
import json

def SBOM_as_tree(flatten_SBOM_data, sbom_file_encoding) :
    """
    Represent a Software Bill of Materials (SBOM) as a Sparse Merkle Tree.

    Parameters:
        flatten_SBOM_data (dict): A dictionary of flattened SBOM fields and their corresponding values.
        sbom_file_encoding (str): The encoding used for encoding the keys and values in the tree.

    Returns:
        tuple: A tuple containing:
            - SparseMerkleTree: An instance of SparseMerkleTree representing the SBOM.
            - str: The name field of the SBOM.
    """
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

import hashlib
from petra.lib.models import SbomNode, FieldNode, ComplexNode

def serialize_tree(root: SbomNode) -> dict :
    tree_dict = root.to_dict()
    
    return tree_dict

def hash(to_hash):
    return hashlib.sha256(to_hash.encode()).digest()

def sameness_verify(node: SbomNode):
    """
    Verifies that the decrypted node files are identical to their pre-encryption state.

    Parameters:
        node (SbomNode): The decrypted, redacted SBOM tree to be verified for sameness
    """
    if isinstance(node, FieldNode):
        #If no data was encrypted, the node is expected to be unchanged, but verify
        if node.decrypted_data:
            assert node.plaintext_hash == hash(node.decrypted_data)
        else:
            assert node.plaintext_hash == hash(f"{node.field_name}{node.field_value}")

    elif isinstance(node, ComplexNode):
        #If no data was encrypted, the node is expected to be unchanged, but verify
        if node.decrypted_data:
            assert node.plaintext_hash == hash(node.decrypted_data)
        else:
            assert node.plaintext_hash == hash(f"{node.complex_type}")

        # Recursively check for each child node
        for child in node.children:
            sameness_verify(child)

    elif isinstance(node, SbomNode):
        # SbomNodes are not encrypted, so only verify each child node
        for child in node.children:
            sameness_verify(child)

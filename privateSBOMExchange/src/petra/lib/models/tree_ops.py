import hashlib
from petra.lib.models import SbomNode, FieldNode, ComplexNode

def serialize_tree(root: SbomNode) -> dict :
    tree_dict = root.to_dict()
    
    return tree_dict

class GetTargetNodes:
    """Visitor that collects the data and hash of each node.
    This is used to test for membership"""

    def __init__(self):
        self.hashes = []

    def visit_field_node(self, node):
        # Append the hash if it existsr
        try:
            node_hash = node.hash
            self.hashes.append(node_hash)
        except AttributeError:
            pass
    def visit_complex_node(self, node):
        # Add the complex node's hash, if available
        try:
            node_hash = node.hash
            self.hashes.append(node_hash)
        except AttributeError:
            pass
        # Visit each child node
        for child in node.children:
            child.accept(self)

    def visit_sbom_node(self, node):
        for child in node.children:
            child.accept(self)

    def get_hashes(self):
        """
        Returns the collected hashes to the caller.
        Called after the tree traversal is complete.
        """
        return self.hashes

def get_membership_proof(root, target_hash):
    """
    Generate a membership proof for a target hash within an SBOM tree.

    Parameters:
    root: The SBOM tree instance.
    target_hash (str or bytes): The hash of the target item to locate in the tree.

    Returns:
    list: A list of lists representing the path taken to locate the target hash in the tree.
    """
    def get_prefix(node):
        """This is same prefix used by MerkleVisitor during hashing"""
        if isinstance(node, SbomNode):
            prefix = (f"{node.purl}").encode() 
        elif isinstance(node, ComplexNode):
            prefix = (f"{node.encrypted_data}{node.complex_type}{node.policy}").encode()
        else: #field node
            prefix = b''
        return prefix
    
    def create_sub_path(node, index, prefix):
        """
        Creates a partial path around a target child node.

        Parameters:
            node: The parent node.
            index: Index of the target child node in parent node.
            prefix (bytes): A byte sequence to prepend to the path.

        Returns:
            list: A list with three parts:
                - `before_target`: `prefix` plus hashes of nodes before the target.
                - `"missing"`: Placeholder for the target node’s position.
                - `after_target`: Hashes of nodes after the target.
        """

        children = [c for c in node.children]
        before_target = prefix + b''.join(sibling.hash for sibling in children[0:index])
        after_target = b''.join(sibling.hash for sibling in children[index+1:])
        
        return [before_target, "missing", after_target]

    def traverse(node, path):
        for i, child in enumerate(node.children):
            if child.hash == target_hash:
                prefix = get_prefix(node)
                sub_path = create_sub_path(node, i, prefix)
                return path + [sub_path] 

            # If the child is not field node, recurse into it
            if isinstance(child, SbomNode) or isinstance(child, ComplexNode):
                traversed_path = traverse(child, path)
                if traversed_path is not None:
                    prefix = get_prefix(node)
                    sub_path = create_sub_path(node, i, prefix)
                    return traversed_path + [sub_path]
        return None 

    # Start traversal from the root node
    if isinstance(root, SbomNode):
        if root.hash == target_hash:
            return []  # Return an empty path as it is the root

        for i, child in enumerate(root.children):
            if child.hash  == target_hash:
                prefix = get_prefix(root)
                sub_path = create_sub_path(root, i, prefix)
                return [sub_path]
                
            # The child is not field node, recurse into it
            if isinstance(child, SbomNode) or isinstance(child, ComplexNode):
                traversed_path = traverse(child, [])
                if traversed_path is not None:
                    prefix = get_prefix(root)
                    sub_path = create_sub_path(root, i, prefix)
                    return traversed_path + [sub_path]
        return None
    else:
        raise Exception(f"{root} must be Sbom Tree")
    
def verify_membership_proof(root_hash, target_hash, proofs):
    """
    Verify the membership proof for a target hash within an SBOM tree.
    """
    def hash(to_hash):
        return hashlib.sha256(to_hash).digest()

    if target_hash == root_hash:
        return True
    
    if proofs is None:
        return False
    
    # Start with `target_hash` and use `proofs` to iteratively build a hash path.
    
    contructed_path_hash = target_hash
    for proof in proofs:
        # Replace the "missing" entry in each proof with the current hash, 
        # join the path, then re-hash to produce the next level's hash.
        proof[proof.index("missing")] = contructed_path_hash
        contructed_path = b''.join(hash for hash in proof)
        contructed_path_hash = hash(contructed_path)

    return contructed_path_hash == root_hash

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
from __future__ import annotations

from ast import Dict
from typing import Any, List

from cpabe import cpabe_encrypt,cpabe_decrypt
from petra.lib.models.policy import PetraPolicy
from petra.lib.crypto import Commitment, digest, DEFAULT_HASH_SIZE_BYTES
from petra.lib.crypto import decrypt_data_AES, encrypt_data_AES
from petra.lib.crypto import ecdsa_sign, ecdsa_sig_verify

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
    def __init__(self, field:str, value:str, policy:dict[str, Any]| None=None):
        """Initialize a FieldNode.

        Parameters
        ----------
        field : str
            The field name.
        value : str
            The field value
        """
        self.field_name = field
        self.field_value = str(value) # need this hack bc sometimes we still pass in non-strings it seems
        self.encrypted_data:str=NODE_PUBLIC
        self.decrypted_data:bytes=None
        self.policy:str=policy
        self.hash:bytes = None

        # sameness properties:
        # the commitment allows consumers to verify the
        # sameness of the content of a node only if they can decrypt it
        self.plaintext_commit:Commitment=Commitment(self.serialize_field_data())

    def accept(self, visitor):
        return visitor.visit_field_node(self)

    def serialize_field_data(self) -> bytes:
        return (f"{self.field_name}:{self.field_value}").encode("utf-8")

    def serialize_for_hashing(self, ser_node_data:bytes, commit_val: bytes) -> bytes:
        # since this function may be used for integrity checking,
        # we parameterize the commitment value and serialize node data
        # that needs to be hashed
        
        # always hash these two fields
        data_to_hash = self.encrypted_data.encode("utf-8")
        data_to_hash += self.policy.encode("utf-8")
        
        if self.encrypted_data != NODE_PUBLIC:
            # we want to obscure this because a duplicated
            # NODE_REDACTED value will leak that it's a field node.
            # we could easily address this elsewhere too 

            data_to_hash += NODE_REDACTED.encode("utf-8")
        else:
            data_to_hash += ser_node_data

        data_to_hash += commit_val

        return data_to_hash

    def get_encryption_value(self) -> bytes:
        # we encrypt the salt of the plaintext commitment
        # to prevent dictionary attacks on other nodes' commitments
        data_to_encrypt = b""

        #if we have a redaction policy, this node's commitment salt and  erase field node data
        if self.policy != "":
            data_to_encrypt = self.plaintext_commit.salt # we put this first because it has fixed length
            data_to_encrypt += self.serialize_field_data() # this needs to match the commitment

            #print(f"policy found for FieldNode {self.field_name}, {self.policy}.")
            self.field_name=NODE_REDACTED
            self.field_value=NODE_REDACTED

        return data_to_encrypt

    def get_sameness_verification_values(self) -> (bytes, bytes):
        # we assume self is either a decrypted node in a redacted tree,
        # or an unredacted node
        if self.encrypted_data != NODE_PUBLIC and self.decrypted_data:
            # this is a decrypted node
            commitment_salt = self.decrypted_data[:DEFAULT_HASH_SIZE_BYTES]
            node_contents = self.decrypted_data[DEFAULT_HASH_SIZE_BYTES:]

            # print("got decrypted value: %s (total size= %s)" %( node_contents.decode("utf-8"), str(len(self.decrypted_data))))
        else:
            # this is an unredacted node
            commitment_salt = self.plaintext_commit.salt
            node_contents = self.serialize_field_data()
            
        # we first recompute our own commitment
        commitment_value = digest(commitment_salt + node_contents)

        '''
        # debug
        if commitment_value != self.plaintext_commit.value:
            print("commitment mismatch for node %s" % node_contents.decode("utf-8"))
        '''

        # now, we recompute our node hash
        # if the hashes match with the redacted node's we can show sameness
        node_hash = digest(self.serialize_for_hashing(node_contents, commitment_value))

        '''
        # debug
        if node_hash != self.hash:
            print("node_hash mismatch for node %s" % node_contents.decode("utf-8"))
        '''

        return commitment_value, node_hash

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to a JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_FIELD
        node_dict['name'] = self.field_name
        node_dict['value'] = self.field_value
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['policy'] = self.policy
        node_dict['plaintext_commit'] = self.plaintext_commit.to_hex()

        if self.hash:
            node_dict['hash'] = self.hash.hex()

        if self.decrypted_data:
            node_dict['decrypted_data'] = self.decrypted_data.hex()

        return node_dict

    @staticmethod
    def from_dict(node_dict: dict) -> FieldNode:
        """ Deserializes the node from a dict that came
            from JSON or other format.
        """
            
        if node_dict['t'] != NODE_FIELD:
            raise ValueError('Expected FieldNode type')
        
        n = FieldNode(node_dict['name'], node_dict['value'])
        hash_hex = node_dict.get('hash')
        n.hash = bytes.fromhex(hash_hex) if hash_hex else None
        n.plaintext_commit = Commitment.from_hex(node_dict['plaintext_commit'])
        n.encrypted_data = node_dict['encrypted_data']
        decrypted_hex = node_dict.get('decrypted_data')
        n.decrypted_data = bytes.fromhex(decrypted_hex) if decrypted_hex else None
        n.policy = node_dict.get('policy')
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
    def __init__(self, complex_type:str,children:List[FieldNode], policy:dict[str, Any] | None=None):
        """Initialize a ComplexNode.

        Parameters
        ----------
        node_type : str
            The type of the complex node.
        children : List[FieldNode]
            A list of FieldNode instances representing the fields of the package.
        """
        self.complex_type:str=complex_type
        self.encrypted_data=NODE_PUBLIC
        self.decrypted_data:bytes=None
        self.children = children
        self.policy:str=policy
        self.hash:bytes = None
        # sameness properties:
        # the commitment allows consumers to verify the
        # sameness of the content of a node only if they can decrypt it
        self.plaintext_commit:Commitment=Commitment(self.complex_type.encode("utf-8"))
        # the plaintext_hash is needed to verify the structural congruence
        # aspect of sameness, i.e., the original SBOM structure is preserved
        # and remember, the commitment value is already H(salt + data)
        data_to_hash = self.plaintext_commit.value
        data_to_hash += b''.join(c.plaintext_commit.value for c in self.children)
        self.plaintext_hash:bytes = digest(data_to_hash)

    def accept(self, visitor):
        return visitor.visit_complex_node(self)

    def serialize_node_data(self) -> bytes:
        return self.complex_type.encode("utf-8")
    
    def serialize_for_hashing(self, commit_value: bytes, plaintext_hash: bytes, children_hashes: bytes) -> bytes:
        data_to_hash = self.encrypted_data.encode("utf-8")
        data_to_hash += self.policy.encode("utf-8")

        data_to_hash += self.serialize_node_data() # may be NODE_REDACTED
        data_to_hash += commit_value
        data_to_hash += plaintext_hash
        
        return data_to_hash + children_hashes

    def get_encryption_value(self) -> bytes:
        # we encrypt the salt of the plaintext commitment
        # to prevent dictionary attacks on other nodes' commitments
        data_to_encrypt = b""

        #if we have a redaction policy, this node's commitment erase node data
        if self.policy != "":
            data_to_encrypt = self.plaintext_commit.salt # we put this first because it has fixed length
            data_to_encrypt += self.serialize_node_data() # this needs to match the commitment

            self.complex_type=NODE_REDACTED

        return data_to_encrypt

    def get_sameness_verification_values(self) -> (bytes, bytes):
        # we assume self is either a decrypted node in a redacted tree,
        # or an unredacted node
        if self.encrypted_data != NODE_PUBLIC and self.decrypted_data:
            commitment_salt = self.decrypted_data[:DEFAULT_HASH_SIZE_BYTES]
            node_contents = self.decrypted_data[DEFAULT_HASH_SIZE_BYTES:]
        else:
            # this is an unredacted node
            commitment_salt = self.plaintext_commit.salt
            node_contents = self.serialize_node_data()

        # we first recompute our own commitment
        commitment_value = digest(commitment_salt + node_contents)

        # next we recompute our plaintext hash
        data_for_pt_hash = commitment_value
        child_verif_hashes = b""
        
        for c in self.children:
            verif_values = c.get_sameness_verification_values()
            data_for_pt_hash += verif_values[0] # the recomputed commitment
            child_verif_hashes += verif_values[1] # the recomputed node hash

        plaintext_hash = digest(data_for_pt_hash)
    
        # now, we recompute our node hash
        # if the hash matches the redacted node's, we know the commitments must match, proving sameness
        data_to_hash = self.serialize_for_hashing(commitment_value, plaintext_hash, child_verif_hashes)

        node_hash = digest(data_to_hash)
        
        return plaintext_hash, node_hash
    
    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to a JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_COMPLEX
        node_dict['type'] = self.complex_type
        node_dict['encrypted_data'] = self.encrypted_data
        node_dict['policy'] = self.policy

        node_dict['plaintext_commit'] = self.plaintext_commit.to_hex()
        node_dict['plaintext_hash'] = self.plaintext_hash.hex()
        
        if self.hash:
            node_dict['hash'] = self.hash.hex()

        if self.decrypted_data:
            node_dict['decrypted_data'] = self.decrypted_data.hex()

        children = dict()
        for c in self.children:
            if c.hash:
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
        n.encrypted_data = node_dict['encrypted_data']
        decrypted_hex = node_dict.get('decrypted_data')
        n.decrypted_data = bytes.fromhex(decrypted_hex) if decrypted_hex else None
        n.policy = node_dict.get('policy')
        hash_hex = node_dict.get('hash')
        n.hash = bytes.fromhex(hash_hex) if hash_hex else None
        n.plaintext_commit = Commitment.from_hex(node_dict['plaintext_commit'])
        n.plaintext_hash = bytes.fromhex(node_dict['plaintext_hash'])

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
    def __init__(self, purl:str, children:List[Node], redaction_policy: dict[str, Any] | None = None):
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
        self.policy: dict[str, Any] = redaction_policy or {}
        self.decrypted_policy={}
        self.encrypted_data={}
        self.redacted_keys=b""
        # sameness properties
        # the plaintext_hash is needed to verify the structural congruence
        # aspect of sameness, i.e., the original SBOM structure is preserved
        data_to_hash=b""
        for policy, key in self.policy.items():
            data_to_hash += key

        for c in self.children:
            if isinstance(c, FieldNode):
                data_to_hash += c.plaintext_commit.value
            elif isinstance(c, ComplexNode) or isinstance(c, SbomNode):
                data_to_hash += c.plaintext_hash
                
        self.plaintext_hash:bytes = digest(data_to_hash)

    def accept(self, visitor):
        # Accept the visitor on the root node and then on all children
        return visitor.visit_sbom_node(self)

    def get_sameness_verification_values(self) -> (bytes, bytes):
        # we start by recomputing our plaintext hash
        decrypted_aes_keys=b""
        for policy, key in self.decrypted_policy.items():
            decrypted_aes_keys = decrypted_aes_keys+key
        
        data_for_pt_hash = decrypted_aes_keys
        child_verif_hashes = b""
        
        for c in self.children:
            verif_values = c.get_sameness_verification_values()
            data_for_pt_hash += verif_values[0] # the recomputed commitment
            child_verif_hashes += verif_values[1] # the recomputed node hash

        plaintext_hash = digest(data_for_pt_hash)

        # then, we recompute our node hash
        encrypted_keys=b""
        for policy, key in self.encrypted_data.items():
            encrypted_keys += key.encode("utf-8")

        node_hash = digest(encrypted_keys + self.purl.encode("utf-8") + plaintext_hash + child_verif_hashes)
        
        return plaintext_hash, node_hash

    def sign(self, signing_key_file: str):
        """
        Generates the ECDSA signature on the SbomNode hash,
        authenticating the root of an SBOM tree.
        """
        self.signature = ecdsa_sign(signing_key_file, self.hash)

    def verify_signature(self, pubkey_file: str) -> bool:
        """
        Verifies the ECDSA signature on the SbomNode hash,
        checking the authenticity of the root of an SBOM tree.
        """
        return ecdsa_sig_verify(pubkey_file, self.hash, self.signature)

    def to_dict(self) -> dict:
        """ Serializes the node into a dict that can be
            passed to JSON or other format.
        """
        node_dict = dict()

        node_dict['t'] = NODE_SBOM
        node_dict['purl'] = self.purl

        node_dict['plaintext_hash'] = self.plaintext_hash.hex()

        if self.hash:
            node_dict['hash'] = self.hash.hex()

        if self.signature:
            node_dict['signature'] = self.signature.hex()
        else:
            node_dict['signature'] = ""

        children = dict()
        for c in self.children:
            if c.hash:
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
        #n.hash = bytes.fromhex(node_dict.get('hash'))
        hash_hex = node_dict.get('hash')
        n.hash = bytes.fromhex(hash_hex) if hash_hex else None
        n.plaintext_hash = bytes.fromhex(node_dict['plaintext_hash'])

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
        
        node.hash = digest(node.serialize_for_hashing(node.serialize_field_data(), node.plaintext_commit.value))
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
        
        node.hash=digest(node.serialize_for_hashing(node.plaintext_commit.value, node.plaintext_hash, children_hashes))
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

        
        for policy, key in node.encrypted_data.items():
            node.redacted_keys += key.encode("utf-8")
        data_to_hash = node.redacted_keys + node.purl.encode("utf-8") + node.plaintext_hash + children_hashes
        node.hash=digest(data_to_hash)
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
        self.__aes_key_dict = dict()

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and encrypt its data using cpabe
        before encryption, the visitor fetch policy associated with node.field_name
        
        Parameters
        ----------
        node : FieldNode
            The field node whose data will be hashed.
        """
        data_to_encrypt = node.get_encryption_value()

        if node.policy != "" and data_to_encrypt:
            # debug
            #print("data_to_encrypt: %s (total size= %s)" % (data_to_encrypt[32:].decode("utf-8"), str(len(data_to_encrypt))))
            #print(f"policy found for FieldNode {node.field_name}, {node.policy}.")
            
            node.encrypted_data = encrypt_data_AES(data_to_encrypt,self.__aes_key_dict[node.policy])
            node.field_name=NODE_REDACTED
            node.field_value=NODE_REDACTED

    def visit_complex_node(self, node:ComplexNode):
        """Encrypt the data for a ComplexNode and assign policies to its children."""
        data_to_encrypt =  node.get_encryption_value()

        if node.policy != "" and data_to_encrypt:
            #debug
            #print(f"policy found for ComplexNode {node.complex_type} , {node.policy}")
            
            node.encrypted_data = encrypt_data_AES(data_to_encrypt,self.__aes_key_dict[node.policy])
            node.complex_type=NODE_REDACTED

        for child in node.children:
            child.accept(self)  # Visit each child

    def visit_sbom_node(self, node: SbomNode):
        """Visit an SbomNode and accept its children without encrypting."""
        
        self.__aes_key_dict=node.policy

        # debug
        #print(self.__aes_key_dict)
        #print(f"Visiting SbomNode '{node.purl}', accepting children.")
        
        # Accept all child nodes 
        for child in node.children:
            child.accept(self)

        # Encrypt AES keys
        for policy, key in node.policy.items():

            node.encrypted_data[policy] = cpabe_encrypt(self.pk, policy, key)
            node.policy[policy]=NODE_REDACTED

class DecryptVisitor:
    """A visitor that traverses nodes in the and decrypts encrypted data
    in each node using the provided secret key."""
    def __init__(self, secret_key):
        # TODO: Get user's secret key from database
        self.secret_key = secret_key
        self.__decrypted_aes_keys={}

    def visit_field_node(self, node: FieldNode):
        """Visit a FieldNode and decrypt its encrypted data using the secret key
        Parameters
        ----------
        node : FieldNode
            The field node whose ciphertext will be decrypted.
        """
        if node.encrypted_data != NODE_PUBLIC:
            try:
                node.decrypted_data = decrypt_data_AES(node.encrypted_data, self.__decrypted_aes_keys[node.policy])

                # debug
                #print(node.decrypted_data)
            except Exception as e:
                print(f"Decryption failed with error: {e}")
        else:
            pass
            #print(f"No encrypted data found for FieldNode '{node.field_name}'.")

    def visit_complex_node(self, node:ComplexNode):  
        # Visit and decrypt all child nodes.
        if node.encrypted_data != NODE_PUBLIC:
            try:
                node.decrypted_data = decrypt_data_AES(node.encrypted_data, self.__decrypted_aes_keys[node.policy])
            except Exception as e:
                print(f"Decryption failed with error: {e}")         
        else:
            pass

        for child in node.children:
            child.accept(self)  

    def visit_sbom_node(self, node: SbomNode): 
        # decrypt AES keys
        if len(node.policy) > 0:
            for policy, encrypted_aes_key in node.encrypted_data.items():
                try:
                    node.decrypted_policy[policy] = bytes(cpabe_decrypt(self.secret_key, encrypted_aes_key))

                    # debug
                    #print("decrypted key: %s" % node.decrypted_policy[policy].hex())
                except Exception as e:
                    print(f"Decryption failed with error: {e}")
                    node.decrypted_policy[policy]=""
        else:
            pass

        # Visit and decrypt all child nodes.  
        self.__decrypted_aes_keys=node.decrypted_policy

        for child in node.children:
            child.accept(self)

        del self.secret_key
        del self.__decrypted_aes_keys

'''
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
'''

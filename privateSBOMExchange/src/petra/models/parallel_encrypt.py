from cpabe import cpabe_encrypt, cpabe_decrypt, ac17_cpabe_encrypt, ac17_cpabe_decrypt
from concurrent.futures import ThreadPoolExecutor
from petra.crypto import encrypt_data_AES, decrypt_data_AES
from petra.models import FieldNode, SbomNode, ComplexNode, NODE_REDACTED, NODE_PUBLIC


class ParallelEncryptVisitor:
    """Visitor that collects node data on traversal, then encrypts in finalize."""

    def __init__(self, pk, decryptor="cpabe"):
        self.pk = pk
        self.workqueue = []
        self.__aes_key_dict = {}
        self.root_sbom_node = None
        if decryptor == "cpabe":
            self.target_func = cpabe_encrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_encrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def finalize(self):
        # AES-encrypt each collected node's data under its per-policy AES key
        def encrypt_node(node_data_pair):
            node, data = node_data_pair
            return node, encrypt_data_AES(data, self.__aes_key_dict[node.policy])

        def wrap_key(policy_key_pair):
            policy, key = policy_key_pair
            return policy, self.target_func(self.pk, policy, key)

        with ThreadPoolExecutor() as executor:
            for node, encrypted_data in executor.map(encrypt_node, self.workqueue):
                node.encrypted_data = encrypted_data

            if self.root_sbom_node:
                for policy, wrapped_key in executor.map(
                    wrap_key, self.__aes_key_dict.items()
                ):
                    self.root_sbom_node.encrypted_data[policy] = wrapped_key
                    self.root_sbom_node.policy[policy] = NODE_REDACTED

    def visit_field_node(self, node: FieldNode):
        data_to_encrypt = node.get_encryption_value()
        if node.policy != "" and data_to_encrypt:
            self.workqueue.append((node, data_to_encrypt))
            node.field_name = NODE_REDACTED
            node.field_value = NODE_REDACTED

    def visit_complex_node(self, node: ComplexNode):
        data_to_encrypt = node.get_encryption_value()
        if node.policy != "" and data_to_encrypt:
            self.workqueue.append((node, data_to_encrypt))
            node.complex_type = NODE_REDACTED
        for child in node.children:
            child.accept(self)

    def visit_sbom_node(self, node: SbomNode):
        self.__aes_key_dict = node.policy
        self.root_sbom_node = node
        for child in node.children:
            child.accept(self)


class ParallelDecryptVisitor:
    """Visitor that collects encrypted nodes on traversal, then decrypts in finalize."""

    def __init__(self, secret_key, decryptor="cpabe"):
        self.secret_key = secret_key
        self.workqueue = []
        self.__decrypted_aes_keys = {}
        if decryptor == "cpabe":
            self.target_func = cpabe_decrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_decrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def finalize(self):
        def decrypt_node(node):
            return node, decrypt_data_AES(
                node.encrypted_data, self.__decrypted_aes_keys[node.policy]
            )

        with ThreadPoolExecutor() as executor:
            for node, decrypted_data in executor.map(decrypt_node, self.workqueue):
                node.decrypted_data = decrypted_data

        del self.__decrypted_aes_keys

    def visit_field_node(self, node: FieldNode):
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append(node)

    def visit_complex_node(self, node: ComplexNode):
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append(node)
        for child in node.children:
            child.accept(self)

    def visit_sbom_node(self, node: SbomNode):
        # CP-ABE-unwrap the per-policy AES keys so the root plaintext_hash can be
        # recomputed
        if len(node.policy) > 0:
            for policy, encrypted_aes_key in node.encrypted_data.items():
                node.decrypted_policy[policy] = bytes(
                    self.target_func(self.secret_key, encrypted_aes_key)
                )
        self.__decrypted_aes_keys = node.decrypted_policy
        for child in node.children:
            child.accept(self)

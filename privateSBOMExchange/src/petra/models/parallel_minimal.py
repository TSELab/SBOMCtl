from cpabe import (
    cpabe_encrypt,
    cpabe_decrypt,
    ac17_cpabe_encrypt,
    ac17_cpabe_decrypt,
    cpabe_decrypt_many,
    cpabe_encrypt_many,
)

from petra.models import FieldNode, SbomNode, ComplexNode, NODE_REDACTED, NODE_PUBLIC


class ParallelEncryptVisitor:
    def __init__(self, pk, decryptor="cpabe"):
        self.pk = pk
        self.workqueue = []
        self.root_sbom_node = None
        if decryptor == "cpabe":
            self.target_func = cpabe_encrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_encrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def finalize(self):
        if self.workqueue:
            policy = [x[2] for x in self.workqueue]
            plaintext = [x[3] for x in self.workqueue]
            pk = self.workqueue[0][1]
            nodes = [x[0] for x in self.workqueue]
            if self.target_func is cpabe_encrypt:
                result = cpabe_encrypt_many(pk, policy, plaintext)
            else:
                result = [
                    self.target_func(pk, pol, pt) for pol, pt in zip(policy, plaintext)
                ]
            for node, encrypted_buffer in zip(nodes, result):
                node.encrypted_data = encrypted_buffer

        if self.root_sbom_node:
            for policy, key in list(self.root_sbom_node.policy.items()):
                self.root_sbom_node.encrypted_data[policy] = self.target_func(
                    self.pk, policy, key
                )
                self.root_sbom_node.policy[policy] = NODE_REDACTED

    def visit_field_node(self, node: FieldNode):
        data_to_encrypt = node.get_encryption_value()
        if node.policy != "" and data_to_encrypt:
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt))

    def visit_complex_node(self, node: ComplexNode):
        data_to_encrypt = node.get_encryption_value()
        if node.policy != "" and data_to_encrypt:
            self.workqueue.append((node, self.pk, node.policy, data_to_encrypt))
        for child in node.children:
            child.accept(self)

    def visit_sbom_node(self, node: SbomNode):
        self.root_sbom_node = node
        for child in node.children:
            child.accept(self)


class ParallelDecryptVisitor:
    def __init__(self, secret_key, decryptor="cpabe"):
        self.secret_key = secret_key
        self.workqueue = []
        if decryptor == "cpabe":
            self.target_func = cpabe_decrypt
        elif decryptor == "ac17":
            self.target_func = ac17_cpabe_decrypt
        else:
            print("I don't support this cpabe scheme, use either cpabe or ac17")

    def finalize(self):
        if len(self.workqueue) < 1:
            return
        sk = self.workqueue[0][1]
        targets = [x[2] for x in self.workqueue]
        nodes = [x[0] for x in self.workqueue]
        if self.target_func is cpabe_decrypt:
            result = cpabe_decrypt_many(sk, targets)
        else:
            result = [self.target_func(sk, ct) for ct in targets]
        for node, decrypted_buffer in zip(nodes, result):
            node.decrypted_data = bytes(decrypted_buffer)

        del self.secret_key

    def visit_field_node(self, node: FieldNode):
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append((node, self.secret_key, node.encrypted_data))

    def visit_complex_node(self, node: ComplexNode):
        if node.encrypted_data != NODE_PUBLIC:
            self.workqueue.append((node, self.secret_key, node.encrypted_data))
        for child in node.children:
            child.accept(self)

    def visit_sbom_node(self, node: SbomNode):
        if len(node.policy) > 0:
            for policy, encrypted_aes_key in node.encrypted_data.items():
                node.decrypted_policy[policy] = bytes(
                    self.target_func(self.secret_key, encrypted_aes_key)
                )

        for child in node.children:
            child.accept(self)

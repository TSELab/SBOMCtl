from smt.tree import TreeMapStore, TreeMemoryStore
from smt.tree import SparseMerkleTree
from smt.utils import DEFAULTVALUE, PLACEHOLDER
from smt.proof import verify_proof
from smt.tree import SparseMerkleTree

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

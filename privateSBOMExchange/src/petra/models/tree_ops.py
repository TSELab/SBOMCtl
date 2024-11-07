from petra.models import SbomNode

def serialize_tree(root: SbomNode) -> dict :
    tree_dict = root.to_dict()
    
    return tree_dict

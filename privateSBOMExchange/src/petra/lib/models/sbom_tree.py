from .abstract_tree import (Node, AbstractVisitor, AbstractFieldNode,
                            AbstractComplexNode, AbstractSbomNode)



class FieldNode(AbstractFieldNode):
    """Represents a field node that is a leaf in the tree, containing an SBOM field as a string.

    Atargetttributes
    ----------
    field_name : str
        The field name stored as a string.
    field_value : str
        The field data stored as a string.
    encrypted_data : bytes or None
        The encrypted data using cpabe, initially set to None and might be set by EncryptVisitor based on the policy
    hash: bytes or None
        The hash of the data, initially set to None, should be set by the MerkleVisitor
    policy: str
        The policy associated with this field, might be set by EncryptVisitor based on the policy

    """
    def __init__(self, field:str,value:str):
        self.field_name = field 
        self.field_value = value 
        #self.encrypted_data:bytes=None 
        #self.hash:bytes=None 
        #self.policy:str=""
        self.visitor = PrintVisitor.visit_field_node


class ComplexNode(AbstractComplexNode):
    """Represents a complex node that can have multiple children of type FieldNode.

    This node represents a dependency that does not have an available SBOM tree in the database.

    Attributes
    ----------
    field_name : str
        "PackageName".
    field_value :str
        The package name.
    encrypted_and_hashed_data : bytes or None
        The encrypted and hashed representation of the package data, initially set to None.
    children : List[FieldNode]
        A list of child FieldNode instances.
    """
    def __init__(self, type_name:str, children:list):
        """Initialize a PackageNode.

        Parameters
        ----------
        package_name : str
            The name of the package.
        children : List[FieldNode]
            A list of FieldNode instances representing the fields of the package.
        """
        self.metadata_type_name:str= type_name  
        #self.metadata_type_value:str=type_value
        #self.encrypted_data=None #store encrypted data when visited by Encrypt visitor
        #self.hash=None #store hashed data when visited by Merkle visitor
        self.children = children
        self.visitor = PrintVisitor.visit_complex_node


class SbomNode(AbstractSbomNode):
    """Represents the root node of a Software Bill of Materials (SBOM) tree.

    This node can have three types of children, all of which are derived from the Node class:
    1. **FieldNode**: Represents a field in an SBOM document.
    2. **ComplexNode**: Represents a complex node that has multiple children.
    3. **SbomNode**: Represents a package dependency that does have an available SBOM tree in the database.

    Attributes
    ----------
    SBOM_name : str
        The name or identifier of the SBOM.
    encrypted_data : bytes or None
        The encrypted data using cpabe, initially set to None and might be set by EncryptVisitor based on the policy
    hash: bytes or None
        The hash of the data, initially set to None, should be set by the MerkleVisitor
    children : List[Node]
        A list of child nodes, which can be FieldNode, PackageNode, or other SbomNode instances.
    signature : 
        signature over the hash, signed by the generator
    purl : str
        package url 
    """
    def __init__(self,name:str,purl, children:list):
        """Initialize an SbomNode.

        Parameters
        ----------
        name : str
            The name of the SBOM.
        purl : str
            package url for the sbom artifact
        children : List[Node]
            A list of child nodes that can be FieldNode, PackageNode, or other SbomNode instances.
        """
        self.SBOM_name=name
        self.children = children 
        self.signature=None
        self.purl:str=purl


class PrintVisitor(AbstractVisitor):
    """Visitors that print the data and hash of each node."""
    def __init__(self):
        self.indent = 0 

    def visit_field_node(self, node, parent):
        indent = "="*self.indent
        print(f"{indent}>Field:{node.field_name}:{node.field_value}")

    def visit_complex_node(self, node, parent):
        indent = "="*self.indent
        print(f"{indent}>}}") 
        self.indent -= 1
          
    def visit_sbom_node(self, node, parent):
        indent = "="*self.indent
        print(f"{indent}}}") 
        self.indent -= 1


    def pre_visit_complex_node(self, node, parent):

        indent = "="*self.indent
        print(f"{indent}>{node.metadata_type_name}:{{") 
        self.indent+=1
          
    def pre_visit_sbom_node(self, node, parent):
        indent = "="*self.indent
        print(f"{indent}>SBOM: {node.SBOM_name}") 
        self.indent+=1



class Node:
    """Base class for a node in the SBOM tree."""
    def accept(self, visitor, parent=None):
        if not visitor:
            NotImplementedError("Must implement accept method.")
        return visitor.visit(self, parent)

    
    def walk(self, visitor, parent):
        """ vanilla implementation of a dfs walk for an abstract node """
    
        if 'children' in dir(self):
            visitor.pre_visit(self, parent)
            for child in self.children:
                child.walk(visitor, self)
        visitor.visit(self, parent)

class AbstractFieldNode(Node):
    pass

class AbstractComplexNode(Node):
    pass

class AbstractSbomNode(Node):
    pass


class AbstractVisitor:

    def visit(self, node, parent):

        if isinstance(node, AbstractFieldNode):
            self.visit_field_node(node, parent)
        elif isinstance(node, AbstractComplexNode):
            self.visit_complex_node(node, parent)
        elif isinstance(node, AbstractSbomNode):
            self.visit_sbom_node(node, parent)

    def visit_field_node(self, node, parent):
        raise Exception("Not implemented")

    def visit_complex_node(self, node, parent):
        raise Exception("Not implemented")
          
    def visit_sbom_node(self, node, parent):
        raise Exception("Not implemented")

    def pre_visit(self, node, parent):

        if isinstance(node, AbstractFieldNode):
            self.pre_visit_field_node(node, parent)
        elif isinstance(node, AbstractComplexNode):
            self.pre_visit_complex_node(node, parent)
        elif isinstance(node, AbstractSbomNode):
            self.pre_visit_sbom_node(node, parent)

    def pre_visit_field_node(self, node, parent):
        # we pass here because in theory there should be 0 set-up for leaves
        pass

    def pre_visit_complex_node(self, node, parent):
        raise Exception("Not implemented")
          
    def pre_visit_sbom_node(self, node, parent):
        raise Exception("Not implemented")

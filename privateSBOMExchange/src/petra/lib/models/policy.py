import tomli

class PetraPolicy:
    """ Defines a policy object used for the selective redaction of
        Petra SBOM trees.
    """
    
    def __init__(self, policy_file: str):
        """Load policies from the given toml file into a dictionary, supporting general and specific cases."""
        self.__policy = {}
        with open(policy_file, "rb") as f:
            self.__policy = tomli.load(f)
        
    def get_field_node_rule(self, field_name: str, parent_policy: str="", field_rules: dict=None) -> str:
        """Get the policy for a FieldNode based on its name and parent policy"""

        # this means all fields under the complex node are being encrypted
        if parent_policy != "":
            return parent_policy

        node_policy = ""
        # if we get here, we have per-field redaction rules
        if field_rules:
            # Check for specific field policies
            field_rule = field_rules.get(field_name)
        
            if field_rule != None:
                node_policy = field_rule
        
        return node_policy

    def get_complex_node_policy(self, complex_node_type: str) -> (str, dict):
        """Returns the policy for a given ComplexNode type."""
        node_policy = ""
        
        type_rules = self.__policy.get(complex_node_type)
        
        if type_rules:
            # Check for * policy( all fields policy ) for the complex node        
            all_fields_rule = type_rules.get("*")

            if all_fields_rule:
                node_policy = all_fields_rule
    
        return node_policy, type_rules

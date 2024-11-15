import tomli

class Config:
    """
    Represents a Petra configuration object.
    """
    
    def __init__(self, file_path: str) -> None:
        """ Parses a TOML-formatted config file
            and populates the underlying config dict.
        """

        self.config_dict = dict()
        self.sbom_files = []
        self.tree_signing_key_file = ""
        self.tree_public_key_file = ""
        self.cpabe_key_files = dict()
        self.cpabe_mk = ""
        self.cpabe_pk = ""
        self.cpabe_policy_files = dict()
        self.cpabe_groups = dict()

        # we may want to catch some exceptions here
        with open(file_path, "rb") as f:
            self.config_dict = tomli.load(f)

        # store the SBOM file names, if any
        sbom_dict = self.config_dict.get("sbom")

        if sbom_dict != None:
            self.sbom_files = sbom_dict.get("files")

        # store the CP-ABE info, if any
        cpabe_dict = self.config_dict.get("cp-abe")

        if cpabe_dict != None:
            # get the CP-ABE keys and policy, if any

            # get the key paths
            master_file_path = cpabe_dict.get("master-key")
            public_file_path = cpabe_dict.get("public-key")

            # only read them in if both are specified.
            # otherwise, raise an error
            if master_file_path != None and public_file_path != None:
                # expect the files to be encoded as a string
                with open(master_file_path, "r") as f:
                    self.cpabe_mk = f.read()
                
                with open(public_file_path, "r") as f:
                    self.cpabe_pk = f.read()
            elif master_file_path == None and public_file_path == None:
                # it's ok to pass when neither is specified.
                # this should trigger Petra to generate the keys
                pass
            else:
                # raise an error since we expect both master and
                # public keys to be specified
                raise ValueError("Master or public key file path missing")

            # get the policy files, if any
            policy_file_dict = cpabe_dict.get("policies")

            if policy_file_dict != None:
                self.cpabe_policy_files = policy_file_dict

            # get the CP-ABE groups, if any
            groups_dict = cpabe_dict.get("groups")

            if groups_dict != None:
                self.cpabe_groups = groups_dict

        # Get the tree signing keys, if any
        signing_dict = self.config_dict.get("signing")

        if signing_dict != None:
            self.tree_signing_key_file = signing_dict.get("signing-key")
            self.tree_public_key_file = signing_dict.get("public-key")

    def get_sbom_files(self) -> list:
        """ Returns the list of SBOM files to read into
            Petra, or an empty list if none were specified
            in the config.
        """
        return self.sbom_files

    def get_tree_signing_key(self) -> str:
        """ Returns the filename of the SBOM tree DER signing key.
            May return None if the key file wasn't specified.
        """
        return self.tree_signing_key_file

    def get_tree_public_key(self) -> str:
        """ Returns the filename of the SBOM tree DER public key.
            May return None if the key file wasn't specified.
        """
        return self.tree_public_key_file

    def get_cpabe_key_files(self) -> dict:
        """ Returns the dict containing the file paths
            to the Petra CP-ABE keys, or None if key files
            weren't specified in the config.
        """
        return self.cpabe_key_files

    def get_cpabe_master_key(self) -> str:
        """ Returns the CP-ABE master key as a string.
            May be empty.
        """
        return self.cpabe_mk

    def get_cpabe_public_key(self) -> str:
        """ Returns the CP-ABE public key as a string.
            May be empty.
        """
        return self.cpabe_pk

    def get_cpabe_policy(self, policy_name:str) -> str:
        """ Return a CP-ABE policy as a string.
            May be empty.
        """
        return self.cpabe_policy_files.get(policy_name)

    def get_cpabe_group(self, group_name:str) -> list:
        """ Return a CP-ABE group as a list.
            May be empty.
        """
        return self.cpabe_groups.get(group_name)

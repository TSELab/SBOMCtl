import json 

def flatten_data(input):
    """
    Flatten a nested dictionary or list into a single-level dictionary.

    Args:
        input (dict or list): The nested data structure to flatten.

    Returns:
        dict: A flattened dictionary with keys representing the paths to the original values.
    """
    out = {}
    def flatten(data, name=''):
        if type(data) is dict:
            for item in data:
                flatten(data[item], name + item + '_')
        elif type(data) is list:
            count = 0
            for item in data:
                flatten(item, name + str(count) + '_')
                count += 1
        else:
            out[name[:-1]] = data

    flatten(input)
    return out


def flatten_SPDX(file_name):
    """
    Read an SPDX SBOM JSON file and flatten its data structure.

    Args:
        file_name (str): The path to the SBOM file.

    Returns:
        tuple: A tuple containing:
            - flatten_sbom (dict): The flattened SBOM data.
            - sbom_file_encoding (str): The encoding of the SBOM file.
    """
    try:
        with open(file_name, 'r') as sbom_file:
            sbom_file_encoding = sbom_file.encoding
            sbom_data = json.load(sbom_file)
            flatten_sbom = flatten_data(sbom_data)
        return flatten_sbom, sbom_file_encoding

    except FileNotFoundError:
        print(f"Error: The file '{file_name}' was not found.")
        return {}, ''
    except json.JSONDecodeError:
        print(f"Error: The file '{file_name}' contains invalid JSON.")
        return {}, ''
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {}, ''

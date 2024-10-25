import json 

def flatten_data(y):
    out = {}
    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def flatten_SPDX(file_name):
    with open (file_name, 'r') as sbom_file:
        sbom_file_encoding=sbom_file.encoding
        sbom_data = json.load(sbom_file)
        result = {}
        #parsed_data = parse_json(data,result,"")
        flatten_sbom=flatten_data(sbom_data)
    return flatten_sbom, sbom_file_encoding



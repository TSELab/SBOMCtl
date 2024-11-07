import sys

try:
    from cpabe import cpabe_decrypt, cpabe_encrypt, cpabe_keygen, cpabe_setup, cpabe_delegate
except:
    print("Can't import cpabe! Make sure you ran maturing develop or installed the cpabe package under src!")

def init_abe():
    return cpabe_setup()

def decrypt_SBOM_field(bundle, field_name, secret_key):
    for key, value in bundle:
        if key == field_name:
            target = value
            break
        print(key)
    else:
        return None
    result_array = cpabe_decrypt(secret_key, target)
    return "".join([chr(x) for x in result_array])

def generate_user_private_key(public_key, master_key, user_attributes):
    return cpabe_keygen(public_key, master_key, user_attributes)

def encrypt_SBOM(flatten_SBOM_data, pub_key, policy):

    result = []
    for key, value in flatten_SBOM_data.items():
        if isinstance(value, bool):
            value=str(value)
        ct = cpabe_encrypt(pub_key, policy, value.encode("utf-8"))
        result.append((key, ct))
    return result




def decrypt_SBOM_field(cpabe_dec_file,field_name,pub_key,priv_key):
    args = make_args(f"3 {pub_key} {priv_key} {field_name}.cpabe")
    print(*args)
        
    cpabe_decrypt_functions = CDLL(cpabe_dec_file)
    cpabe_decrypt_functions.main.restype = c_int
    cpabe_decrypt_functions.main.argtypes = c_int,POINTER(c_char_p)
    cpabe_decrypt_functions.main(len(args), args)
    cpabe_decrypt_functions.reset_globals()

def generate_user_private_key(cpabe_keygen_file,priv_key,pub_key,master_key,user_attributes):
    cpabe_keygen_functions = CDLL(cpabe_keygen_file)

    cpabe_keygen_functions.main.restype = c_int
    cpabe_keygen_functions.main.argtypes = c_int,POINTER(c_char_p)
    #cpabe-keygen -o sara_priv_key pub_key master_key test/policy

    args = make_args(f'5 -o {priv_key} {pub_key} {master_key} {user_attributes}')
    print(*args)
    cpabe_keygen_functions.main(len(args), args)

def encrypt_SBOM(flatten_SBOM_data, cpabe_enc_file,pub_key,policy):
    
    #ToDo: policy needs to be splitted for each field
    cpabe_encrypt_functions = CDLL(cpabe_enc_file)
    print(type(cpabe_encrypt_functions))
    cpabe_encrypt_functions.main.restype = c_int
    cpabe_encrypt_functions.main.argtypes = c_int,POINTER(c_char_p)     

    for key,value in flatten_SBOM_data.items():
        with open (key,"w") as SBOM_field_file:
            if isinstance(value, bool):
                value=str(value)
            SBOM_field_file.write(value)                     
        args = make_args(f"3 {pub_key} {key} {policy}")
        print(*args)
        cpabe_encrypt_functions.main(len(args), args)
        cpabe_encrypt_functions.reset_globals()



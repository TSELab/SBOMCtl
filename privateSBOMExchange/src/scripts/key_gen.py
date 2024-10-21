import secrets

from key_db import create_table, store_key, get_key


def generate_key(bit_length=256):
    return secrets.randbits(bit_length)

def generate_and_store_key(user_id):
    key = generate_key()
    store_key(user_id, key) 

def get_stored_key(user_id):
    key = get_key(user_id)
    return key
    


if __name__ == "__main__":
    create_table()  

    users = [f"user{i}" for i in range(1, 6)]

    for user in users:
        generate_and_store_key(user)
        print(f"Generated key for {user}")
    
    print("\nRetrieving stored keys:")
    for user in users:
        key = get_stored_key(user)

        if key:
            print(f"Key for {user}: {key}")
        else:
            print(f"No key found for {user}")
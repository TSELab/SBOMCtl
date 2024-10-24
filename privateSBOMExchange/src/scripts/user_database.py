import sqlite3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def init_db(db_name="users.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS Users (
                        key TEXT PRIMARY KEY,
                        organizationName TEXT,
                        commonName TEXT,
                        public_key BLOB
                      )''')
    conn.commit()
    return conn


def hash_public_key(public_key_bytes):
    public_key_hash = hashes.Hash(hashes.SHA256())
    public_key_hash.update(public_key_bytes)
    return public_key_hash.finalize().hex()


def StoreUserInDB(conn, user):
    cursor = conn.cursor()

    public_key_bytes = user["key"]
    public_key_hash = hash_public_key(public_key_bytes) 
    organization_name = user["organizationName"]
    common_name = user["commonName"]

    cursor.execute('''
        INSERT OR REPLACE INTO Users (key, organizationName, commonName, public_key)
        VALUES (?, ?, ?, ?)''', (public_key_hash, organization_name, common_name, public_key_bytes))
    conn.commit()


def GetUserRoleFromDB(conn, public_key_bytes):
    cursor = conn.cursor()

    public_key_hash = hash_public_key(public_key_bytes)

    cursor.execute('SELECT commonName FROM Users WHERE key = ?', (public_key_hash,))
    role = cursor.fetchone()

    if role:
        return role[0]
    return None

def extract_public_key_from_cert(cert_file_path="github.com"):
    with open(cert_file_path, 'rb') as cert_file:
        cert_data = cert_file.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem
    
if __name__ == "__main__":

    conn = init_db("users.db") 

    user = {
        "organizationName": "Test Organization",
        "commonName": "Test User",
        "key": extract_public_key_from_cert()
    }

    StoreUserInDB(conn, user)

    public_key_bytes = user["key"]
    current_role = GetUserRoleFromDB(conn, public_key_bytes)


    assert current_role == user["commonName"], "Role retrieval failed!"
    print("User role retrieved correctly")


    conn.close()


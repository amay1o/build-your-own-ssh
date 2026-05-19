import socket
import os


from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5555

# CREATE SERVER SOCKET
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))

server.listen()

print(f"[*] Server listening on {HOST}:{PORT}")

# ACCEPT CLIENT
client_socket, client_address = server.accept()

print(f"[+] Connection from {client_address}")

# LOAD SERVER PRIVATE KEY
with open("keys/server_private.pem", "rb") as f:
    server_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# LOAD SERVER PUBLIC KEY
with open("keys/server_public.pem", "rb") as f:
    server_public_key_data = f.read()

# SEND SERVER PUBLIC KEY TO CLIENT
client_socket.send(server_public_key_data)

print("[*] Server public key sent.")

# RECEIVE ENCRYPTED AES SESSION KEY
encrypted_session_key = client_socket.recv(4096)

# DECRYPT AES SESSION KEY USING RSA
session_key = server_private_key.decrypt(
    encrypted_session_key,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("[*] AES session key securely received.")

# CREATE AES OBJECT
aes = AESGCM(session_key)

# =========================
# AUTHENTICATION PHASE
# =========================

# GENERATE RANDOM CHALLENGE
challenge = os.urandom(32)

# ENCRYPT CHALLENGE
challenge_nonce = os.urandom(12)

encrypted_challenge = aes.encrypt(
    challenge_nonce,
    challenge,
    None
)

# SEND NONCE + CIPHERTEXT
client_socket.send(
    challenge_nonce + encrypted_challenge
)

print("[*] Authentication challenge sent.")

# RECEIVE SIGNATURE
signature = client_socket.recv(4096)

# LOAD CLIENT PUBLIC KEY DIRECTLY
with open("keys/client_public.pem", "rb") as f:
    client_public_key = serialization.load_pem_public_key(
        f.read()
    )

# VERIFY SIGNATURE
try:

    client_public_key.verify(
        signature,
        challenge,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("[+] Client authentication successful.")

    # SEND AUTH SUCCESS
    success_nonce = os.urandom(12)

    success_message = aes.encrypt(
        success_nonce,
        b"AUTH_SUCCESS",
        None
    )

    client_socket.send(
        success_nonce + success_message
    )

except Exception as e:

    print("[-] Authentication failed.")
    print(e)

    # SEND AUTH FAILED
    fail_nonce = os.urandom(12)

    fail_message = aes.encrypt(
        fail_nonce,
        b"AUTH_FAILED",
        None
    )

    client_socket.send(
        fail_nonce + fail_message
    )

# CLOSE CONNECTION
client_socket.close()

server.close()

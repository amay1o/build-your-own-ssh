import socket
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5555

# CREATE CLIENT SOCKET
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print("[*] Connected to server.")

# RECEIVE SERVER PUBLIC KEY
server_public_key_data = client.recv(4096)

server_public_key = serialization.load_pem_public_key(
    server_public_key_data
)

print("[*] Server public key received.")

# GENERATE AES SESSION KEY
session_key = os.urandom(32)

# ENCRYPT AES SESSION KEY
encrypted_session_key = server_public_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# SEND ENCRYPTED SESSION KEY
client.send(encrypted_session_key)

print("[*] AES session key securely sent.")

# CREATE AES OBJECT
aes = AESGCM(session_key)

# LOAD CLIENT PRIVATE KEY
with open("keys/client_private.pem", "rb") as f:
    client_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# RECEIVE ENCRYPTED CHALLENGE
data = client.recv(4096)

challenge_nonce = data[:12]

challenge_ciphertext = data[12:]

challenge = aes.decrypt(
    challenge_nonce,
    challenge_ciphertext,
    None
)

print("[*] Authentication challenge received.")

# SIGN CHALLENGE
signature = client_private_key.sign(
    challenge,
    padding.PSS(
        mgf=padding.MGF1(
            hashes.SHA256()
        ),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# SEND SIGNATURE
client.send(signature)

print("[*] Challenge signed and sent.")

# RECEIVE AUTH RESULT
response = client.recv(4096)

response_nonce = response[:12]

response_ciphertext = response[12:]

result = aes.decrypt(
    response_nonce,
    response_ciphertext,
    None
).decode()

print("[SERVER]:", result)

# CHECK AUTH
if result != "AUTH_SUCCESS":

    print("Authentication failed.")

    client.close()

    exit()

# =========================
# REMOTE SHELL
# =========================

while True:

    command = input("ssh> ")

    # ENCRYPT COMMAND
    command_nonce = os.urandom(12)

    encrypted_command = aes.encrypt(
        command_nonce,
        command.encode(),
        None
    )

    # SEND COMMAND
    client.send(
        command_nonce + encrypted_command
    )

    # EXIT
    if command.lower() == "exit":
        break

    # RECEIVE ENCRYPTED OUTPUT
    data = client.recv(16384)

    output_nonce = data[:12]

    output_ciphertext = data[12:]

    output = aes.decrypt(
        output_nonce,
        output_ciphertext,
        None
    ).decode()

    print(output)

# CLOSE CONNECTION
client.close()
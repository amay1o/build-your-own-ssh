import socket
import os
import subprocess

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

# SEND SERVER PUBLIC KEY
client_socket.send(server_public_key_data)

print("[*] Server public key sent.")

# RECEIVE ENCRYPTED AES SESSION KEY
encrypted_session_key = client_socket.recv(4096)

# DECRYPT AES SESSION KEY
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

challenge_nonce = os.urandom(12)

encrypted_challenge = aes.encrypt(
    challenge_nonce,
    challenge,
    None
)

client_socket.send(
    challenge_nonce + encrypted_challenge
)

print("[*] Authentication challenge sent.")

# RECEIVE SIGNATURE
signature = client_socket.recv(4096)

# LOAD CLIENT PUBLIC KEY
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

    fail_nonce = os.urandom(12)

    fail_message = aes.encrypt(
        fail_nonce,
        b"AUTH_FAILED",
        None
    )

    client_socket.send(
        fail_nonce + fail_message
    )

    client_socket.close()
    server.close()
    exit()

# =========================
# REMOTE SHELL PHASE
# =========================

while True:

    # RECEIVE ENCRYPTED COMMAND
    data = client_socket.recv(4096)

    command_nonce = data[:12]

    command_ciphertext = data[12:]

    command = aes.decrypt(
        command_nonce,
        command_ciphertext,
        None
    ).decode()

    print(f"[CLIENT COMMAND]: {command}")

    # EXIT COMMAND
    if command.lower() == "exit":
        print("[*] Client disconnected.")
        break

    try:

        # EXECUTE COMMAND
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        if output == "":
            output = "[*] Command executed with no output."

    except Exception as e:

        output = f"Error executing command: {str(e)}"

    # ENCRYPT OUTPUT
    output_nonce = os.urandom(12)

    encrypted_output = aes.encrypt(
        output_nonce,
        output.encode(),
        None
    )

    # SEND NONCE + CIPHERTEXT
    client_socket.send(
        output_nonce + encrypted_output
    )

# CLOSE CONNECTION
client_socket.close()

server.close()
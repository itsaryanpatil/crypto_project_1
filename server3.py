import socket
import threading
import json
import base64
import random
import os
import hashlib
import subprocess
from sympy import nextprime, mod_inverse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# ---------------------------
# Utility functions for credentials
# ---------------------------
CREDENTIALS_FILE = "credentials.json"

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    else:
        return {}

def save_credentials(credentials):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------------------
# Fuzzy IBE Implementation
# ---------------------------
class FuzzyIBE:
    def __init__(self, universe_size, d, bits=2048):
        self.p = self.get_large_prime(bits)
        self.g = self.get_generator(self.p)
        self.y = random.randint(1, self.p - 1)
        self.t = {i: random.randint(1, self.p - 1) for i in range(1, universe_size + 1)}
        self.T = {i: pow(self.g, self.t[i], self.p) for i in self.t}
        self.Y = self.bilinear_map(self.g, self.g, self.y, self.p)
        self.master_key = (self.y, self.t)
        self.d = d

        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.verification_key = self.signing_key.public_key()

        self.universe_size = universe_size

    @staticmethod
    def get_large_prime(bits=2048):
        return nextprime(random.getrandbits(bits))

    @staticmethod
    def get_generator(p):
        return random.randint(2, p - 1)

    @staticmethod
    def bilinear_map(g1, g2, exponent, p):
        return (pow(g1, exponent, p) * pow(g2, exponent, p)) % p

    @staticmethod
    def random_polynomial(degree, constant, p):
        coeffs = [random.randint(1, p - 1) for _ in range(degree)]
        coeffs.append(constant)
        return lambda x: sum(coeffs[i] * pow(x, i, p) for i in range(len(coeffs))) % p

    @staticmethod
    def interpolation_coeff(i, S, p):
        num, denom = 1, 1
        for j in S:
            j_val = int(j)
            if j_val != i:
                num = (num * (-j_val)) % p
                denom = (denom * (i - j_val)) % p
        return (num * mod_inverse(denom, p)) % p

    @staticmethod
    def select_d_elements(overlap, d):
        return list(overlap)[:d]

    def keygen(self, identity):
        q = self.random_polynomial(degree=self.d - 1, constant=self.y, p=self.p)
        return {int(i): pow(self.g, q(i) * mod_inverse(self.t[int(i)], self.p), self.p) for i in identity}

    def sign_message(self, message):
        message_bytes = str(message).encode()
        signature = self.signing_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, signature, message):
        try:
            message_bytes = str(message).encode()
            signature_bytes = base64.b64decode(signature)
            self.verification_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def encrypt(self, identity, message):
        # This method is used only to encrypt small messages such as session keys.
        message_bytes = str(message).encode()
        message_int = int.from_bytes(message_bytes, byteorder='big')
        signature = self.sign_message(message)
        s = random.randint(1, self.p - 1)
        E_prime = (message_int * pow(self.Y, s, self.p)) % self.p
        E_i = {str(i): pow(self.T[int(i)], s, self.p) for i in identity}
        return {
            "identity": [str(i) for i in identity],
            "E_prime": E_prime,
            "E_i": E_i,
            "s": s,
            "signature": signature
        }

    def decrypt(self, private_key, ciphertext):
        identity = set(ciphertext["identity"])
        overlap = set(str(k) for k in private_key.keys()).intersection(identity)
        if len(overlap) < self.d:
            raise ValueError("Insufficient attribute match for decryption")
        _ = self.select_d_elements(overlap, self.d)  # Not used further in this simplified demo.
        message_int = (ciphertext["E_prime"] * mod_inverse(pow(self.Y, ciphertext["s"], self.p), self.p)) % self.p
        
        message_length = (message_int.bit_length() + 7) // 8
        message_bytes = message_int.to_bytes(message_length, byteorder='big')
        message = message_bytes.decode()
        
        if self.verify_signature(ciphertext["signature"], message):
            return message
        else:
            raise ValueError("Signature verification failed!")

    def serialize_keys(self):
        signing_pem = self.signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        verification_pem = self.verification_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return signing_pem, verification_pem

    def get_public_params(self):
        signing_pem, verification_pem = self.serialize_keys()
        return {
            "p": self.p,
            "g": self.g,
            "T": self.T,
            "Y": self.Y,
            "d": self.d,
            "universe_size": self.universe_size,
            "signing_key": signing_pem,
            "verification_key": verification_pem
        }

    @classmethod
    def from_params(cls, params):
        instance = cls(params["universe_size"], params["d"], bits=2048)
        instance.p = params["p"]
        instance.g = params["g"]
        # Convert keys of T back to integers.
        instance.T = {int(k): v for k, v in params["T"].items()}
        instance.Y = params["Y"]
        instance.d = params["d"]
        instance.universe_size = params["universe_size"]
        instance.signing_key = serialization.load_pem_private_key(params["signing_key"].encode(), password=None)
        instance.verification_key = serialization.load_pem_public_key(params["verification_key"].encode())
        return instance

# ---------------------------
# Hybrid Encryption Helpers using OpenSSL AES-256-CBC
# ---------------------------
def hybrid_encrypt(ibe, symmetric_identity, plaintext):
    # plaintext is expected as a string
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = plaintext
    # Generate random 32-byte AES key and 16-byte IV
    session_key = os.urandom(32)
    iv = os.urandom(16)
    key_hex = session_key.hex()
    iv_hex = iv.hex()
    # Encrypt plaintext using OpenSSL AES-256-CBC
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key_hex, "-iv", iv_hex, "-nosalt"],
        input=plaintext_bytes,
        capture_output=True
    )
    if proc.returncode != 0:
        raise Exception("OpenSSL encryption failed: " + proc.stderr.decode())
    ciphertext = proc.stdout
    # Encrypt the session key using IBE.
    session_key_b64 = base64.b64encode(session_key).decode('utf-8')
    encrypted_key = ibe.encrypt(symmetric_identity, session_key_b64)
    # Return hybrid message
    return {
        "type": "hybrid",
        "iv": iv_hex,
        "encrypted_key": encrypted_key,
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def hybrid_decrypt(ibe, private_key, hybrid_msg):
    iv_hex = hybrid_msg["iv"]
    encrypted_key = hybrid_msg["encrypted_key"]
    ciphertext_b64 = hybrid_msg["ciphertext"]
    # Decrypt the session key using IBE.
    session_key_b64 = ibe.decrypt(private_key, encrypted_key)
    session_key = base64.b64decode(session_key_b64)
    key_hex = session_key.hex()
    ciphertext = base64.b64decode(ciphertext_b64)
    # Decrypt ciphertext using OpenSSL AES-256-CBC
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key_hex, "-iv", iv_hex, "-nosalt"],
        input=ciphertext,
        capture_output=True
    )
    if proc.returncode != 0:
        raise Exception("OpenSSL decryption failed: " + proc.stderr.decode())
    plaintext_bytes = proc.stdout
    return plaintext_bytes.decode('utf-8')

# ---------------------------
# Global Setup for Server
# ---------------------------
universe_size = 10
d = 3
ibe = FuzzyIBE(universe_size, d, bits=2048)
server_identity = {1, 2, 3}
server_private_key = ibe.keygen(server_identity)

clients = []
credentials = load_credentials()

# Helper functions for message framing
def send_json(conn, data):
    message = json.dumps(data) + "\n"
    conn.sendall(message.encode('utf-8'))

def recv_json(conn_file):
    line = conn_file.readline()
    if not line:
        return None
    return json.loads(line)

def handle_client(conn, addr):
    global credentials
    conn_file = conn.makefile('r')
    try:
        data = recv_json(conn_file)
        if data is None:
            conn.close()
            return
        msg = data
        if msg.get("type") not in ["signup", "login"]:
            send_json(conn, {"type": "error", "message": "Invalid authentication type."})
            conn.close()
            return
        
        username = msg.get("username")
        password = msg.get("password")
        if not username or not password:
            send_json(conn, {"type": "error", "message": "Username and password required."})
            conn.close()
            return

        hashed_pw = hash_password(password)
        
        if msg["type"] == "signup":
            if username in credentials:
                send_json(conn, {"type": "error", "message": "Username already exists."})
                conn.close()
                return
            client_identity = set(msg.get("identity", []))
            credentials[username] = {"password": hashed_pw, "identity": list(client_identity)}
            save_credentials(credentials)
            send_json(conn, {"type": "info", "message": "Signup successful."})
        elif msg["type"] == "login":
            if username not in credentials:
                send_json(conn, {"type": "error", "message": "Username does not exist."})
                conn.close()
                return
            stored_hashed = credentials[username]["password"]
            if hashed_pw != stored_hashed:
                send_json(conn, {"type": "error", "message": "Incorrect password."})
                conn.close()
                return
            client_identity = set(credentials[username]["identity"])
            send_json(conn, {"type": "info", "message": "Login successful."})
        else:
            send_json(conn, {"type": "error", "message": "Unknown authentication type."})
            conn.close()
            return

        print(f"[INFO] Client {addr} authenticated as {username} with identity {client_identity}")
        client_private_key = ibe.keygen(client_identity)

        setup_msg = {
            "type": "setup",
            "client_private_key": client_private_key,
            "public_params": ibe.get_public_params(),
            "server_identity": list(server_identity)
        }
        send_json(conn, setup_msg)
        clients.append({"conn": conn, "addr": addr, "username": username, "identity": client_identity})

        while True:
            data = recv_json(conn_file)
            if not data:
                break
            try:
                # Expecting a hybrid message
                if data.get("type") != "hybrid":
                    print(f"[ERROR] Unexpected message type from {addr}")
                    continue
                plaintext = hybrid_decrypt(ibe, server_private_key, data)
                if plaintext.startswith("file:"):
                    parts = plaintext.split(":", 2)
                    if len(parts) == 3:
                        _, filename, _ = parts
                        # For file transfers, the ciphertext is decrypted via hybrid_decrypt,
                        # so the file has already been recovered as plaintext.
                        # In this demo, we simply print a confirmation.
                        print(f"[FILE] Received file: {filename}")
                    else:
                        print("[ERROR] Incorrect file message format.")
                else:
                    print(f"[MESSAGE] From {addr} ({username}): {plaintext}")
            except Exception as e:
                print(f"[ERROR] Decryption failed from {addr} ({username}): {e}")
    except Exception as e:
        print(f"[ERROR] Exception with client {addr}: {e}")
    finally:
        print(f"[INFO] Client {addr} disconnected.")
        conn.close()
        for c in clients:
            if c["conn"] == conn:
                clients.remove(c)
                break

def start_server():
    host = "0.0.0.0"
    port = 33333
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[INFO] Server listening on {host}:{port}")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

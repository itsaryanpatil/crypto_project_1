import socket
import os
import threading
import json
import base64
import random
import subprocess
from sympy import nextprime, mod_inverse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

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
        _ = self.select_d_elements(overlap, self.d)
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
        instance.T = {int(k): v for k, v in params["T"].items()}
        instance.Y = params["Y"]
        instance.d = params["d"]
        instance.universe_size = params["universe_size"]
        instance.signing_key = serialization.load_pem_private_key(params["signing_key"].encode(), password=None)
        instance.verification_key = serialization.load_pem_public_key(params["verification_key"].encode())
        return instance

# Hybrid Encryption Helpers (same as on the server)
def hybrid_encrypt(ibe, symmetric_identity, plaintext):
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = plaintext
    session_key = os.urandom(32)
    iv = os.urandom(16)
    key_hex = session_key.hex()
    iv_hex = iv.hex()
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key_hex, "-iv", iv_hex, "-nosalt"],
        input=plaintext_bytes,
        capture_output=True
    )
    if proc.returncode != 0:
        raise Exception("OpenSSL encryption failed: " + proc.stderr.decode())
    ciphertext = proc.stdout
    session_key_b64 = base64.b64encode(session_key).decode('utf-8')
    encrypted_key = ibe.encrypt(symmetric_identity, session_key_b64)
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
    session_key_b64 = ibe.decrypt(private_key, encrypted_key)
    session_key = base64.b64decode(session_key_b64)
    key_hex = session_key.hex()
    ciphertext = base64.b64decode(ciphertext_b64)
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key_hex, "-iv", iv_hex, "-nosalt"],
        input=ciphertext,
        capture_output=True
    )
    if proc.returncode != 0:
        raise Exception("OpenSSL decryption failed: " + proc.stderr.decode())
    plaintext_bytes = proc.stdout
    return plaintext_bytes.decode('utf-8')

# Helper functions for message framing
def send_json(sock, data):
    message = json.dumps(data) + "\n"
    sock.sendall(message.encode('utf-8'))

def recv_json(sock_file):
    line = sock_file.readline()
    if not line:
        return None
    return json.loads(line)

# ---------------------------
# Listener Thread: Receives messages from server
# ---------------------------
def listen_server(sock, ibe, client_private_key):
    sock_file = sock.makefile('r')
    while True:
        try:
            data = recv_json(sock_file)
            if not data:
                print("[INFO] Server closed the connection.")
                sock.close()
                exit(0)
            if data.get("type") != "hybrid":
                print("[ERROR] Unexpected message type from server.")
                continue
            plaintext = hybrid_decrypt(ibe, client_private_key, data)
            if plaintext.startswith("file:"):
                parts = plaintext.split(":", 2)
                if len(parts) == 3:
                    filename = parts[1]
                    # For file transfers, the file content is included in the decrypted text.
                    print(f"[FILE] Received file '{filename}'. Check file saving logic as needed.")
                else:
                    print(f"[MESSAGE] {plaintext}")
            else:
                print(f"[MESSAGE] {plaintext}")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[ERROR] Failed to decrypt message: {e}")
        except (ConnectionResetError, BrokenPipeError):
            print("[INFO] Server closed the connection.")
            sock.close()
            exit(0)

# ---------------------------
# Sending Thread: Reads input and sends messages
# ---------------------------
def client_send(sock, ibe, client_private_key, server_identity):
    while True:
        try:
            msg = input()
            if msg.lower() == "exit":
                print("[INFO] Closing connection.")
                sock.close()
                exit(0)
            if msg.startswith("file:"):
                filepath = msg[5:].strip()
                if not os.path.exists(filepath):
                    print(f"[ERROR] File '{filepath}' not found.")
                    continue
                try:
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    # For file transfers, prepend a marker so the receiver knows it's a file.
                    filename = os.path.basename(filepath)
                    message = f"file:{filename}:".encode('utf-8') + file_data
                    # hybrid_encrypt expects a string or bytes.
                    cipher = hybrid_encrypt(ibe, server_identity, message)
                except Exception as e:
                    print(f"[ERROR] Could not read file: {e}")
                    continue
            else:
                cipher = hybrid_encrypt(ibe, server_identity, msg)
            send_json(sock, cipher)
        except (ConnectionResetError, BrokenPipeError):
            print("[INFO] Server closed the connection.")
            sock.close()
            exit(0)

# ---------------------------
# Main Client Function with Signup/Login
# ---------------------------
def start_client():
    global ibe
    host = input("Enter server IP (default localhost): ") or "localhost"
    port = 33333
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server.")
        exit(0)

    action = input("Do you want to signup or login? [signup/login]: ").strip().lower()
    if action not in ["signup", "login"]:
        print("Invalid option.")
        sock.close()
        exit(0)

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    auth_msg = {
        "type": action,
        "username": username,
        "password": password
    }
    if action == "signup":
        identity_input = input("Enter your attributes (comma-separated integers): ")
        identity = [int(x.strip()) for x in identity_input.split(",") if x.strip().isdigit()]
        auth_msg["identity"] = identity

    send_json(sock, auth_msg)

    sock_file = sock.makefile('r')
    data = recv_json(sock_file)
    if not data:
        print("[ERROR] Server closed the connection.")
        sock.close()
        exit(0)
    
    response = data
    if response.get("type") == "error":
        print("Authentication error:", response.get("message"))
        sock.close()
        exit(0)
    elif response.get("type") == "info":
        print(response.get("message"))

    data = recv_json(sock_file)
    if not data:
        print("[ERROR] Server closed the connection.")
        sock.close()
        exit(0)

    setup = data
    if setup.get("type") != "setup":
        print("Invalid setup message from server.")
        sock.close()
        exit(0)

    client_private_key = {int(k): int(v) for k, v in setup["client_private_key"].items()}
    public_params = setup["public_params"]
    server_identity = set(setup["server_identity"])

    ibe = FuzzyIBE.from_params(public_params)
    print("[INFO] Setup complete. You can now send messages. Type 'exit' to quit.")

    threading.Thread(target=listen_server, args=(sock, ibe, client_private_key), daemon=True).start()
    client_send(sock, ibe, client_private_key, server_identity)

if __name__ == "__main__":
    start_client()

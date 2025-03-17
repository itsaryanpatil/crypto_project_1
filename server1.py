import socket
import threading
import json
import base64
import random
from sympy import nextprime, mod_inverse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# ---------------------------
# Fuzzy IBE Implementation
# ---------------------------
class FuzzyIBE:
    def __init__(self, universe_size, d, bits=256):
        self.p = self.get_large_prime(bits)
        self.g = self.get_generator(self.p)
        self.y = random.randint(1, self.p - 1)
        self.t = {i: random.randint(1, self.p - 1) for i in range(1, universe_size + 1)}
        self.T = {i: pow(self.g, self.t[i], self.p) for i in self.t}
        self.Y = self.bilinear_map(self.g, self.g, self.y, self.p)
        self.master_key = (self.y, self.t)
        self.d = d

        # ECDSA keys for signing/verification
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.verification_key = self.signing_key.public_key()

        self.universe_size = universe_size

    @staticmethod
    def get_large_prime(bits=256):
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
            j_val = int(j)  # Convert the attribute to an integer
            if j_val != i:
                num = (num * (-j_val)) % p
                denom = (denom * (i - j_val)) % p
        return (num * mod_inverse(denom, p)) % p


    @staticmethod
    def select_d_elements(overlap, d):
        return list(overlap)[:d]

    def keygen(self, identity):
        # Note: identity is expected as a set (of integers).
        q = self.random_polynomial(degree=self.d - 1, constant=self.y, p=self.p)
        # Return a dict mapping attribute (as string) to private share
        return {str(i): pow(self.g, q(i) * mod_inverse(self.t[i], self.p), self.p) for i in identity}

    def sign_message(self, message):
        message_bytes = str(message).encode()
        signature = self.signing_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        # Base64 encode signature so it can be serialized as text
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
    # Convert the message to an integer representation (if needed)
        message_bytes = str(message).encode()
        message_int = int.from_bytes(message_bytes, byteorder='big')
        
        signature = self.sign_message(message)
        s = random.randint(1, self.p - 1)
        E_prime = (message_int * pow(self.Y, s, self.p)) % self.p
        
        # Convert the attribute key to string when accessing T
        E_i = {str(i): pow(self.T[str(i)], s, self.p) for i in identity}
        
        return {
            "identity": [str(i) for i in identity],
            "E_prime": E_prime,
            "E_i": E_i,
            "s": s,
            "signature": signature
        }


    def decrypt(self, private_key, ciphertext):
        identity = set(ciphertext["identity"])
        overlap = set(private_key.keys()).intersection(identity)
        if len(overlap) < self.d:
            raise ValueError("Insufficient attribute match for decryption")
        S = self.select_d_elements(overlap, self.d)
        exponent = sum(
            self.interpolation_coeff(int(i), S, self.p) * pow(private_key[i], ciphertext["s"], self.p)
            for i in S
        ) % self.p
        message_int = (ciphertext["E_prime"] * mod_inverse(pow(self.Y, ciphertext["s"], self.p), self.p)) % self.p

        # Convert the integer back to bytes and then decode to string.
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
        instance = cls(params["universe_size"], params["d"])
        instance.p = params["p"]
        instance.g = params["g"]
        instance.T = params["T"]
        instance.Y = params["Y"]
        instance.d = params["d"]
        instance.universe_size = params["universe_size"]
        instance.signing_key = serialization.load_pem_private_key(params["signing_key"].encode(), password=None)
        instance.verification_key = serialization.load_pem_public_key(params["verification_key"].encode())
        return instance

# ---------------------------
# Global Setup for Server
# ---------------------------
universe_size = 10
d = 3
ibe = FuzzyIBE(universe_size, d)
# For the server we fix an identity (e.g. attributes {1,2,3})
server_identity = {1, 2, 3}
server_private_key = ibe.keygen(server_identity)

# List to keep track of connected clients.
# Each client is a dict with keys: conn, addr, identity
clients = []

# ---------------------------
# Client Connection Handler
# ---------------------------
def handle_client(conn, addr):
    try:
        # First, receive the client’s identity
        data = conn.recv(4096).decode()
        msg = json.loads(data)
        if msg["type"] != "identity":
            conn.close()
            return
        client_identity = set(msg["identity"])
        print(f"[INFO] Client {addr} connected with identity {client_identity}")

        # Generate the client’s private key (for decryption)
        client_private_key = ibe.keygen(client_identity)

        # Send back a setup message containing:
        # - The client’s private key (so the client can decrypt messages addressed to it)
        # - The public fuzzy IBE parameters (including the signing/verification keys)
        # - The server’s identity (so the client can encrypt messages to the server)
        setup_msg = {
            "type": "setup",
            "client_private_key": client_private_key,
            "public_params": ibe.get_public_params(),
            "server_identity": list(server_identity)
        }
        conn.sendall(json.dumps(setup_msg).encode())

        # Add this client to the global clients list
        clients.append({"conn": conn, "addr": addr, "identity": client_identity})

        # Now continuously listen for messages from this client.
        # Clients send messages encrypted using the server’s identity.
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                cipher = json.loads(data.decode())
                plaintext = ibe.decrypt(server_private_key, cipher)
                print(f"[MESSAGE] From {addr}: {plaintext}")
            except Exception as e:
                print(f"[ERROR] Decryption failed from {addr}: {e}")
    except Exception as e:
        print(f"[ERROR] Exception with client {addr}: {e}")
    finally:
        print(f"[INFO] Client {addr} disconnected.")
        conn.close()
        for c in clients:
            if c["conn"] == conn:
                clients.remove(c)
                break

# ---------------------------
# Broadcast from Server Console
# ---------------------------
def broadcast_message(message):
    # The server encrypts the message for each client using the client’s identity.
    for client in clients:
        try:
            cipher = ibe.encrypt(client["identity"], message)
            client["conn"].sendall(json.dumps(cipher).encode())
        except Exception as e:
            print(f"[ERROR] Broadcasting to {client['addr']} failed: {e}")

def server_input():
    while True:
        msg = input()
        if msg.lower() == "exit":
            print("[INFO] Shutting down server.")
            for client in clients:
                client["conn"].close()
            break
        # If the message indicates a file (prefix "file:"), read the file
        if msg.startswith("file:"):
            filepath = msg[5:].strip()
            try:
                with open(filepath, "r") as f:
                    file_data = f.read()
                message = f"file:{filepath}:{file_data}"
            except Exception as e:
                print(f"[ERROR] Could not read file: {e}")
                continue
        else:
            message = msg
        broadcast_message(message)

# ---------------------------
# Main Server Function
# ---------------------------
def start_server():
    host = "0.0.0.0"
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[INFO] Server listening on {host}:{port}")

    # Start a thread for the server console input
    threading.Thread(target=server_input, daemon=True).start()

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

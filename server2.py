import socket
import threading
import json
import random
import os
import hashlib
from sympy import nextprime, mod_inverse

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
    def __init__(self, universe_size, d, bits=256):
        self.p = self.get_large_prime(bits)
        self.g = random.randint(2, self.p - 1)
        self.y = random.randint(1, self.p - 1)
        self.t = {i: random.randint(1, self.p - 1) for i in range(1, universe_size + 1)}
        self.T = {i: pow(self.g, self.t[i], self.p) for i in self.t}
        self.Y = pow(self.g, self.y, self.p)
        self.d = d
        self.universe_size = universe_size

    @staticmethod
    def get_large_prime(bits=256):
        return nextprime(random.getrandbits(bits))

    def keygen(self, identity):
        q = lambda x: (self.y + sum(random.randint(1, self.p - 1) * pow(x, i, self.p) for i in range(self.d - 1))) % self.p
        return {str(i): pow(self.g, q(i) * mod_inverse(self.t[i], self.p), self.p) for i in identity}

# ---------------------------
# Server Setup
# ---------------------------
universe_size = 10
d = 3
ibe = FuzzyIBE(universe_size, d)
server_identity = {1, 2, 3}
credentials = load_credentials()

def handle_client(conn, addr):
    global credentials
    try:
        data = json.loads(conn.recv(4096).decode())
        username, password = data.get("username"), data.get("password")
        hashed_pw = hash_password(password)

        if data["type"] == "signup":
            if username in credentials:
                conn.sendall(json.dumps({"error": "Username exists"}).encode())
                return
            identity = set(data.get("identity", []))
            credentials[username] = {"password": hashed_pw, "identity": list(identity)}
            save_credentials(credentials)
            conn.sendall(json.dumps({"message": "Signup successful"}).encode())

        elif data["type"] == "login":
            if username not in credentials or credentials[username]["password"] != hashed_pw:
                conn.sendall(json.dumps({"error": "Invalid credentials"}).encode())
                return
            identity = set(credentials[username]["identity"])
            print(identity)
        else:
            conn.sendall(json.dumps({"error": "Invalid request"}).encode())
            return

        # Generate the private key dynamically
        private_key = ibe.keygen(identity)

        setup_msg = {
            "type": "setup",
            "client_private_key": private_key,
            "public_params": {"p": ibe.p, "g": ibe.g, "Y": ibe.Y, "d": ibe.d},
            "server_identity": list(server_identity)
        }
        conn.sendall(json.dumps(setup_msg).encode())

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print("Server listening on port 12345")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()


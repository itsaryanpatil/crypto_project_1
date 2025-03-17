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
# (Same as on the server)
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
        q = self.random_polynomial(degree=self.d - 1, constant=self.y, p=self.p)
        return {str(i): pow(self.g, q(i) * mod_inverse(self.t[i], self.p), self.p) for i in identity}

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
# Global Variables (set after setup)
# ---------------------------
ibe = None
client_private_key = None
server_identity = None

# ---------------------------
# Listener Thread: Receives messages from server
# ---------------------------
def listen_server(sock):
    global ibe, client_private_key
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            cipher = json.loads(data.decode())
            # Decrypt message using the client’s private key
            plaintext = ibe.decrypt(client_private_key, cipher)
            # If the message indicates a file, save it.
            if str(plaintext).startswith("file:"):
                parts = str(plaintext).split(":", 2)
                if len(parts) == 3:
                    filename = parts[1]
                    filedata = parts[2]
                    with open("received_" + filename, "w") as f:
                        f.write(filedata)
                    print(f"[FILE] Received file '{filename}' and saved as 'received_{filename}'")
                else:
                    print(f"[MESSAGE] {plaintext}")
            else:
                print(f"[MESSAGE] {plaintext}")
        except Exception as e:
            print(f"[ERROR] Failed to decrypt message: {e}")
            break

# ---------------------------
# Sending Thread: Reads input and sends messages
# ---------------------------
def client_send(sock):
    global ibe, client_private_key, server_identity
    while True:
        msg = input()
        if msg.lower() == "exit":
            sock.close()
            break
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
        # Encrypt message using the server’s identity
        cipher = ibe.encrypt(server_identity, message)
        sock.sendall(json.dumps(cipher).encode())

# ---------------------------
# Main Client Function
# ---------------------------
def start_client():
    global ibe, client_private_key, server_identity
    host = input("Enter server IP (default localhost): ") or "localhost"
    port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    # Ask the user for its identity (a comma-separated list of attributes)
    identity_input = input("Enter your attributes (comma-separated integers): ")
    identity = set(int(x.strip()) for x in identity_input.split(",") if x.strip().isdigit())
    # Send identity message to the server
    id_msg = {"type": "identity", "identity": list(identity)}
    sock.sendall(json.dumps(id_msg).encode())
    # Receive the setup message from the server
    data = sock.recv(4096).decode()
    setup = json.loads(data)
    if setup["type"] != "setup":
        print("Invalid setup message from server.")
        sock.close()
        return
    # Save the client’s private key and public parameters
    client_private_key = {k: int(v) for k, v in setup["client_private_key"].items()}
    public_params = setup["public_params"]
    server_identity = set(setup["server_identity"])
    # Create the FuzzyIBE instance from the received parameters.
    ibe = FuzzyIBE.from_params(public_params)
    print("[INFO] Setup complete. You can now send messages. Type 'exit' to quit.")

    # Start threads for receiving and sending messages
    threading.Thread(target=listen_server, args=(sock,), daemon=True).start()
    client_send(sock)

if __name__ == "__main__":
    start_client()

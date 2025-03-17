import socket
import json

class FuzzyIBE:
    def __init__(self, p, g, Y, d):
        self.p = p
        self.g = g
        self.Y = Y
        self.d = d

    def decrypt(self, private_key, ciphertext):
        message_int = (ciphertext["E_prime"] * pow(self.Y, -ciphertext["s"], self.p)) % self.p
        return message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big').decode()

def start_client():
    host = input("Enter server IP: ") or "localhost"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, 12345))
    
    action = input("Do you want to signup or login? [signup/login]: ").strip().lower()
    username, password = input("Username: "), input("Password: ")
    msg = {"type": action, "username": username, "password": password}
    
    if action == "signup":
        identity = list(map(int, input("Enter attributes (comma-separated): ").split(",")))
        msg["identity"] = identity
    
    sock.sendall(json.dumps(msg).encode())

    if action == "signup":
        return  # Stop after signup since no private key is needed yet

    # Receive setup data (private key & public params) after login
    setup = json.loads(sock.recv(4096).decode())

    print("\n🔑 **Client Private Key:**")
    print(json.dumps(setup["client_private_key"], indent=4))
    
    print("\n🌍 **Public Parameters:**")
    print(json.dumps(setup["public_params"], indent=4))

    print("\n🏢 **Server Identity:**", setup["server_identity"])

    # Initialize IBE with public parameters
    ibe = FuzzyIBE(setup["public_params"]["p"], setup["public_params"]["g"], setup["public_params"]["Y"], setup["public_params"]["d"])
    
    print("\n✅ Setup complete. Ready for secure communication!")

if __name__ == "__main__":
    start_client()


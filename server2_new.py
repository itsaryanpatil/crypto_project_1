import socket
import json
import threading
import random

# Simulated user database
users = {}

def encrypt_document(document, policy):
    """Simulated encryption based on attribute policy"""
    E_prime = random.randint(1, 10**50)  # Simulated encryption result
    s = random.randint(1, 10**50)  # Simulated secret value
    return {"E_prime": E_prime, "s": s, "policy": policy}

def decrypt_document(username, encrypted_doc):
    """Threshold-based decryption: User must have 50% of the required attributes"""
    if username not in users:
        return {"status": "fail", "message": "User not found"}

    user_attributes = set(users[username]["attributes"])
    required_policy = set(encrypted_doc["policy"])

    # Calculate percentage of matching attributes
    matches = len(user_attributes.intersection(required_policy))
    total_required = len(required_policy)

    if matches >= total_required / 2:
        return {"status": "success", "decrypted_message": "Decryption successful! Original document retrieved."}
    else:
        return {"status": "fail", "message": f"ACCESS DENIED: {matches}/{total_required} attributes match"}

def handle_client(client_socket):
    """Handles client requests"""
    request = json.loads(client_socket.recv(4096).decode())

    if request["type"] == "signup":
        username = request["username"]
        password = request["password"]
        attributes = request["attributes"]

        if username in users:
            response = {"status": "fail", "message": "User already exists"}
        else:
            users[username] = {"password": password, "attributes": attributes}
            response = {"status": "success", "message": f"User {username} registered with attributes {attributes}"}

    elif request["type"] == "encrypt":
        document = request["document"]
        policy = request["policy"]
        response = {"status": "success", "encrypted_doc": encrypt_document(document, policy)}

    elif request["type"] == "decrypt":
        username = request["username"]
        encrypted_doc = request["encrypted_doc"]
        response = decrypt_document(username, encrypted_doc)

    elif request["type"] == "add_attribute":
        username = request["username"]
        new_attribute = request["new_attribute"]

        if username in users:
            users[username]["attributes"].append(new_attribute)
            response = {"status": "success", "message": f"Attribute '{new_attribute}' added to {username}"}
        else:
            response = {"status": "fail", "message": "User not found"}

    elif request["type"] == "remove_attribute":
        username = request["username"]
        remove_attribute = request["remove_attribute"]

        if username in users:
            if remove_attribute in users[username]["attributes"]:
                users[username]["attributes"].remove(remove_attribute)
                response = {"status": "success", "message": f"Attribute '{remove_attribute}' removed from {username}"}
            else:
                response = {"status": "fail", "message": "Attribute not found"}
        else:
            response = {"status": "fail", "message": "User not found"}

    else:
        response = {"status": "fail", "message": "Invalid request"}

    client_socket.sendall(json.dumps(response).encode())
    client_socket.close()

def start_server():
    """Starts the server"""
    host = "localhost"
    port = 12345

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Server running on {host}:{port}...")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
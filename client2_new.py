import socket
import json

def send_request(request):
    """Send request to the server and return response"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))
    client.sendall(json.dumps(request).encode())

    response = json.loads(client.recv(4096).decode())
    client.close()
    return response

while True:
    action = input("Do you want to signup, encrypt, decrypt, add_attribute, or remove_attribute? ").strip().lower()

    if action == "signup":
        username = input("Enter a username: ")
        password = input("Enter a password: ")
        attributes = input("Enter attributes (comma-separated, e.g., Finance,HR,IT,Manager): ").split(",")

        response = send_request({"type": "signup", "username": username, "password": password, "attributes": attributes})
        print(response["message"])

    elif action == "encrypt":
        document = input("Enter the document to encrypt: ")
        policy = input("Enter the access policy (comma-separated attributes): ").split(",")

        response = send_request({"type": "encrypt", "document": document, "policy": policy})
        print("Encrypted document JSON:", json.dumps(response["encrypted_doc"]))

    elif action == "decrypt":
        username = input("Enter your username: ")
        encrypted_json = input("Paste the encrypted document JSON: ")

        try:
            encrypted_doc = json.loads(encrypted_json)
            response = send_request({"type": "decrypt", "username": username, "encrypted_doc": encrypted_doc})
            if "message" in response:
                print(response["message"])  # Print failure messages
            else:
                print("Decryption successful! Document contents:")
                print(response)  # Print the decrypted document
        except json.JSONDecodeError:
            print("Invalid JSON format")

    elif action == "add_attribute":
        username = input("Enter your username: ")
        new_attribute = input("Enter the new attribute to add: ")

        response = send_request({"type": "add_attribute", "username": username, "new_attribute": new_attribute})
        print(response["message"])

    elif action == "remove_attribute":
        username = input("Enter your username: ")
        remove_attribute = input("Enter the attribute to revoke: ")

        response = send_request({"type": "remove_attribute", "username": username, "remove_attribute": remove_attribute})
        print(response["message"])

    else:
        print("Invalid option.")
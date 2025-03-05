import socket
import threading
import json
import subprocess
import tempfile
import os
import struct
import base64

# A simple in-memory user database.
# For demonstration only – do not use plaintext passwords in production.
user_db = {"user": "pass"}

# Helper functions for sending/receiving messages with a 4-byte length header.
def send_msg(sock, data: bytes):
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    return recvall(sock, msg_len)

def aes_decrypt(ciphertext: bytes, sym_key: str, iv: str) -> str:
    with tempfile.NamedTemporaryFile(delete=False) as ct_file:
        ct_file.write(ciphertext)
        ct_filename = ct_file.name
    with tempfile.NamedTemporaryFile(delete=False) as dec_file:
        dec_filename = dec_file.name
    subprocess.run([
         "openssl", "enc", "-d", "-aes-256-cbc",
         "-K", sym_key,
         "-iv", iv,
         "-in", ct_filename,
         "-out", dec_filename
    ], check=True)
    with open(dec_filename, "r") as f:
        decrypted_message = f.read()
    os.remove(ct_filename)
    os.remove(dec_filename)
    return decrypted_message

def aes_encrypt(message: str, sym_key: str, iv: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as pt_file:
        pt_file.write(message)
        pt_filename = pt_file.name
    with tempfile.NamedTemporaryFile(delete=False) as ct_file:
        ct_filename = ct_file.name
    subprocess.run([
         "openssl", "enc", "-aes-256-cbc",
         "-K", sym_key,
         "-iv", iv,
         "-in", pt_filename,
         "-out", ct_filename
    ], check=True)
    with open(ct_filename, "rb") as f:
        ciphertext = f.read()
    os.remove(pt_filename)
    os.remove(ct_filename)
    return ciphertext

def handle_client(client_sock, addr):
    print(f"[+] Connection from {addr}")
    try:
        # --- Login/Registration Phase ---
        login_data = recv_msg(client_sock)
        if not login_data:
            print("[-] No login data received.")
            client_sock.close()
            return

        login_msg = json.loads(login_data.decode('utf-8'))
        command = login_msg.get("command")
        username = login_msg.get("username")
        password = login_msg.get("password")
        client_pubkey_pem = login_msg.get("public_key")

        if command == "login":
            if username not in user_db or user_db[username] != password:
                print("[-] Invalid credentials from", addr)
                error_response = "Invalid credentials. Connection closing."
                send_msg(client_sock, error_response.encode('utf-8'))
                client_sock.close()
                return
            print(f"[+] Login from {username} accepted.")
        elif command == "register":
            if username in user_db:
                print("[-] Registration failed: User already exists", addr)
                error_response = "User already exists. Connection closing."
                send_msg(client_sock, error_response.encode('utf-8'))
                client_sock.close()
                return
            else:
                user_db[username] = password
                print(f"[+] Registered new user: {username}.")
        else:
            print("[-] Unknown command received.")
            client_sock.close()
            return

        # --- Symmetric Key Exchange ---
        sym_key = os.urandom(32).hex()   # 256-bit key as hex
        iv = os.urandom(16).hex()          # 128-bit IV as hex
        key_payload = f"{sym_key}:{iv}"
        print(f"[+] Generated symmetric key and IV for {username}.")

        # Save client's public key to a temporary file.
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as pubkey_file:
            pubkey_file.write(client_pubkey_pem)
            pubkey_filename = pubkey_file.name

        # Save the symmetric key payload to a temporary file.
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as keyfile:
            keyfile.write(key_payload)
            keyfile_filename = keyfile.name

        # Encrypt the symmetric key payload using RSA with the client's public key.
        with tempfile.NamedTemporaryFile(delete=False) as enc_file:
            enc_filename = enc_file.name

        subprocess.run([
            "openssl", "rsautl",
            "-encrypt",
            "-pubin",
            "-inkey", pubkey_filename,
            "-in", keyfile_filename,
            "-out", enc_filename
        ], check=True)

        with open(enc_filename, "rb") as f:
            encrypted_blob = f.read()

        os.remove(pubkey_filename)
        os.remove(keyfile_filename)
        os.remove(enc_filename)

        # Send the encrypted symmetric key blob to the client.
        send_msg(client_sock, encrypted_blob)
        print("[+] Sent encrypted symmetric key to client.")

        # --- Continuous Communication Loop ---
        while True:
            aes_enc_b64 = recv_msg(client_sock)
            if not aes_enc_b64:
                print(f"[-] Connection closed by {addr}")
                break

            try:
                aes_ciphertext = base64.b64decode(aes_enc_b64)
                decrypted_message = aes_decrypt(aes_ciphertext, sym_key, iv)
            except Exception as e:
                print("[-] Error decrypting message:", e)
                break

            print(f"[{addr}] Received: {decrypted_message.strip()}")

            # Send back an echo response.
            response_text = f"Server echo: {decrypted_message.strip()}"
            try:
                encrypted_response = aes_encrypt(response_text, sym_key, iv)
                response_b64 = base64.b64encode(encrypted_response)
                send_msg(client_sock, response_b64)
            except Exception as e:
                print("[-] Error encrypting response:", e)
                break

    except Exception as e:
        print("[-] Exception handling client:", e)
    finally:
        client_sock.close()
        print(f"[-] Connection from {addr} closed.")

def main():
    HOST = '0.0.0.0'
    PORT = 2222
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_sock, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[+] Server shutting down.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()

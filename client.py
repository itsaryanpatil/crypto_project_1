import socket
import json
import subprocess
import tempfile
import os
import struct
import base64

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

# AES encryption using OpenSSL AES-256-CBC.
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

# AES decryption using OpenSSL AES-256-CBC.
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

def main():
    HOST = '127.0.0.1'  # or the server's IP address
    PORT = 2222

    print(f"[+] Connecting to {HOST}:{PORT} ...")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST, PORT))

    # --- Interactive Mode: Choose Login or Registration ---
    while True:
        print("Select an option:")
        print("1) Login")
        print("2) Register")
        choice = input("Enter 1 or 2: ").strip()
        if choice in ["1", "2"]:
            break
        print("Invalid selection. Please try again.")

    command = "login" if choice == "1" else "register"
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    # === RSA Key Generation ===
    # Generate a temporary RSA key pair using OpenSSL.
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as priv_key_file:
        priv_key_filename = priv_key_file.name
    subprocess.run(["openssl", "genrsa", "-out", priv_key_filename, "2048"], check=True)

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as pub_key_file:
        pub_key_filename = pub_key_file.name
    subprocess.run(["openssl", "rsa", "-in", priv_key_filename, "-pubout", "-out", pub_key_filename], check=True)

    with open(pub_key_filename, "r") as f:
        client_public_key = f.read()
    os.remove(pub_key_filename)

    # === Login/Registration Phase ===
    login_message = {
        "command": command,
        "username": username,
        "password": password,
        "public_key": client_public_key
    }
    login_message_bytes = json.dumps(login_message).encode('utf-8')
    send_msg(client_sock, login_message_bytes)
    print(f"[+] Sent {command} message.")

    # === Receive Encrypted Symmetric Key Blob ===
    encrypted_blob = recv_msg(client_sock)
    if encrypted_blob is None:
        print("[-] No response received from server. Exiting.")
        client_sock.close()
        return

    # Save the encrypted blob to a temporary file.
    with tempfile.NamedTemporaryFile(delete=False) as enc_file:
        enc_filename = enc_file.name
        enc_file.write(encrypted_blob)

    # Decrypt the symmetric key payload using RSA decryption with our private key.
    with tempfile.NamedTemporaryFile(delete=False) as dec_file:
        dec_filename = dec_file.name
    subprocess.run([
         "openssl", "rsautl",
         "-decrypt",
         "-inkey", priv_key_filename,
         "-in", enc_filename,
         "-out", dec_filename
    ], check=True)
    with open(dec_filename, "r") as f:
        key_payload = f.read().strip()

    # Clean up temporary files.
    os.remove(enc_filename)
    os.remove(dec_filename)
    os.remove(priv_key_filename)  # Private key no longer needed after key exchange.

    # The payload is expected to be in the form "sym_key:iv"
    try:
        sym_key, iv = key_payload.split(":")
    except ValueError:
        print("[-] Failed to parse symmetric key payload.")
        client_sock.close()
        return

    print("[+] Symmetric key exchange complete. You may now chat with the server.")

    # === Communication Loop ===
    try:
        while True:
            message = input("Enter message (or 'exit' to quit): ")
            if message.lower() == "exit":
                break

            # Encrypt the message using AES encryption.
            aes_ciphertext = aes_encrypt(message, sym_key, iv)
            aes_enc_b64 = base64.b64encode(aes_ciphertext)
            send_msg(client_sock, aes_enc_b64)

            # Wait for the server's response.
            response_b64 = recv_msg(client_sock)
            if not response_b64:
                print("[-] Server closed the connection.")
                break
            aes_response = base64.b64decode(response_b64)
            response_text = aes_decrypt(aes_response, sym_key, iv)
            print("Server response:", response_text.strip())
    except Exception as e:
        print("[-] Error during communication:", e)
    finally:
        client_sock.close()
        print("[-] Connection closed.")

if __name__ == "__main__":
    main()

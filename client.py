import sys
import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def gen_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return priv, pub, pub_pem

def encrypt_rsa(pub_key, text):
    data = text.encode('utf-8')
    chunk_size = 128
    out = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        enc = pub_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        out.append(enc)
    return b''.join(out)

def decrypt_rsa(priv_key, ciphertext):
    chunk_size = 256
    out = []
    for i in range(0, len(ciphertext), chunk_size):
        chunk = ciphertext[i:i+chunk_size]
        dec = priv_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        out.append(dec)
    return b''.join(out).decode('utf-8')

def send_msg(sock, payload):
    header = len(payload).to_bytes(4, byteorder='big')
    sock.sendall(header + payload)

def recv_msg(sock):
    try:
        header = sock.recv(4)
        if not header:
            return None
        if len(header) < 4:
            return header
        length = int.from_bytes(header, byteorder='big')
        if length > 65536 or length % 256 != 0:
            rest = sock.recv(4096)
            return header + rest
        
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)
    except Exception:
        return None

client_priv_key, client_pub_key, client_pub_pem = gen_rsa_keypair()
server_pub_key = None
data_sock = None
running = True

def receive_loop():
    global running
    while running:
        raw = recv_msg(data_sock)
        if not raw:
            break
        print("Received encrypted message")
        try:
            decrypted = decrypt_rsa(client_priv_key, raw)
            parts = decrypted.split("\n\n", 1)
            code = parts[0].strip()
            body = parts[1].strip() if len(parts) > 1 else ""

            if body == "Login successful":
                print(f"{code} status code received. Login successful")
            elif body.startswith("Users currently connected:"):
                print(f"{code} status code received. {body}")
            elif body == "Message sent.":
                print(f"{code} status code received. Message sent.")
            elif body.startswith("Broadcast message from "):
                print(f"{code} status code received.")
                print(body)
            elif ":" in body:
                print(f"{code} status code received.")
                print(body)
            elif body == "":
                print(f"{code} status code received.")
            else:
                print(f"{code} status code received.")
                if body:
                    print(body)
        except Exception as e:
            pass

def main():
    global server_pub_key, data_sock, running

    print("Starting client...")

    while running:
        try:
            cmd_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd_input:
            continue

        if cmd_input.startswith("connect"):
            parts = cmd_input.split()
            if len(parts) >= 3:
                ip = parts[1]
                port = int(parts[2])
                try:
                    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ctrl_sock.connect((ip, port))
                    ctrl_sock.sendall(cmd_input.encode('utf-8'))

                    resp = ctrl_sock.recv(4096).decode('utf-8', errors='ignore')
                    ctrl_sock.close()

                    resp_parts = resp.split("\n\n", 1)
                    code = resp_parts[0].strip()
                    data_section = resp_parts[1] if len(resp_parts) > 1 else ""

                    data_lines = data_section.splitlines()
                    data_port = int(data_lines[0].strip())
                    srv_pub_pem = "\n".join(data_lines[1:]).strip()

                    server_pub_key = serialization.load_pem_public_key(srv_pub_pem.encode('utf-8'))

                    print(f"200 status code received. Starting data connection on port {data_port}")

                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.connect((ip, data_port))

                    t = threading.Thread(target=receive_loop, daemon=True)
                    t.start()
                except Exception as e:
                    print(f"Connection failed: {e}")
            else:
                print("Usage: connect <ip> <port>")

        elif cmd_input.startswith("login"):
            parts = cmd_input.split()
            if len(parts) >= 2 and data_sock and server_pub_key:
                uname = parts[1]
                payload = f"login\n{uname}\n{client_pub_pem}"
                enc = encrypt_rsa(server_pub_key, payload)
                send_msg(data_sock, enc)
            else:
                if not data_sock:
                    print("Must connect first.")

        elif cmd_input == "who":
            if data_sock and server_pub_key:
                enc = encrypt_rsa(server_pub_key, "who")
                send_msg(data_sock, enc)

        elif cmd_input.startswith("broadcast"):
            if data_sock and server_pub_key:
                enc = encrypt_rsa(server_pub_key, cmd_input)
                send_msg(data_sock, enc)

        elif cmd_input.startswith("private"):
            if data_sock and server_pub_key:
                enc = encrypt_rsa(server_pub_key, cmd_input)
                send_msg(data_sock, enc)

        elif cmd_input == "quit":
            if data_sock and server_pub_key:
                enc = encrypt_rsa(server_pub_key, "quit")
                send_msg(data_sock, enc)
                time.sleep(0.3)
                running = False
                break
            else:
                break

if __name__ == "__main__":
    main()

import sys
import socket
import threading
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

clients = {}
clients_lock = threading.Lock()

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
            # Fallback if un-framed raw bytes sent
            return header
        length = int.from_bytes(header, byteorder='big')
        # Check if length is reasonable (e.g. RSA blocks: 256, 512, 1024, etc.)
        if length > 65536 or length % 256 != 0:
            # Might be raw ciphertext without 4-byte header
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

def handle_client(data_conn, data_addr, server_priv_key):
    current_user = None
    while True:
        raw_data = recv_msg(data_conn)
        if not raw_data:
            break

        try:
            decrypted_str = decrypt_rsa(server_priv_key, raw_data)
        except Exception:
            continue

        print("Received encrypted message")
        lines = decrypted_str.strip().splitlines()
        if not lines:
            continue

        first_line = lines[0].strip()

        if first_line == "login":
            if len(lines) >= 3:
                uname = lines[1].strip()
                pub_pem = "\n".join(lines[2:]).strip()
                print(f"Login requested by: {uname}")

                with clients_lock:
                    if uname in clients:
                        client_pub = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
                        err_res = "500\n\nUsername already taken"
                        send_msg(data_conn, encrypt_rsa(client_pub, err_res))
                        break
                    else:
                        client_pub = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
                        clients[uname] = {
                            'conn': data_conn,
                            'pub_key': client_pub
                        }
                        current_user = uname
                        res = "200\n\nLogin successful"
                        send_msg(data_conn, encrypt_rsa(client_pub, res))
            else:
                pass

        elif first_line == "who":
            print("Who requested. Sending users.")
            with clients_lock:
                other_users = [u for u in clients.keys() if u != current_user]
                user_str = ", ".join(other_users) if other_users else "none"
                if current_user in clients:
                    client_pub = clients[current_user]['pub_key']
                    res = f"200\n\nUsers currently connected: {user_str}"
                    send_msg(data_conn, encrypt_rsa(client_pub, res))

        elif first_line.startswith("broadcast"):
            parts = first_line.split(' ', 1)
            msg_text = parts[1] if len(parts) > 1 else ""
            print(f"Broadcast requested by {current_user}")
            print(f"Message: {msg_text}")

            res = f"200\n\nBroadcast message from {current_user}: {msg_text}"
            with clients_lock:
                for u, info in list(clients.items()):
                    try:
                        send_msg(info['conn'], encrypt_rsa(info['pub_key'], res))
                    except Exception:
                        pass

        elif first_line.startswith("private"):
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                target = parts[1]
                pmsg = parts[2]
                print(f"Private message from {current_user} to {target}")

                with clients_lock:
                    if target in clients and current_user in clients:
                        sender_pub = clients[current_user]['pub_key']
                        send_msg(data_conn, encrypt_rsa(sender_pub, "200\n\nMessage sent."))

                        target_info = clients[target]
                        target_res = f"200\n\n{current_user}: {pmsg}"
                        send_msg(target_info['conn'], encrypt_rsa(target_info['pub_key'], target_res))
                    elif current_user in clients:
                        sender_pub = clients[current_user]['pub_key']
                        send_msg(data_conn, encrypt_rsa(sender_pub, "500\n\nUser not found"))

        elif first_line == "quit":
            print(f"Quit requested by {current_user}")
            with clients_lock:
                if current_user and current_user in clients:
                    user_pub = clients[current_user]['pub_key']
                    send_msg(data_conn, encrypt_rsa(user_pub, "200\n\n"))
                    del clients[current_user]
            break

    if current_user:
        with clients_lock:
            if current_user in clients:
                del clients[current_user]
    data_conn.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8991

    print("Starting server...")
    print("Creating RSA keypair")
    server_priv_key, server_pub_key, server_pub_pem = gen_rsa_keypair()
    print("RSA keypair created")
    print("Creating server socket")

    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control_sock.bind(('', port))
    control_sock.listen(5)
    print("Awaiting connections...")

    while True:
        try:
            ctrl_conn, ctrl_addr = control_sock.accept()
            req = ctrl_conn.recv(1024).decode('utf-8', errors='ignore')
            if req.startswith("connect"):
                data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_listener.bind(('', 0))
                data_listener.listen(1)
                data_port = data_listener.getsockname()[1]

                print("Connection requested. Creating data socket")
                res = f"200\n\n{data_port}\n{server_pub_pem}"
                ctrl_conn.sendall(res.encode('utf-8'))
                ctrl_conn.close()

                data_conn, data_addr = data_listener.accept()
                data_listener.close()

                t = threading.Thread(target=handle_client, args=(data_conn, data_addr, server_priv_key), daemon=True)
                t.start()
            else:
                ctrl_conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()

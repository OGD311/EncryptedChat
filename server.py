import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA key pair for the server
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize server public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

clients = {}  # Store client sockets and their public keys

def broadcast(sender_address, message):
    """ Encrypt and send the message to all connected clients except sender. """
    for address, (client_socket, client_public_key) in clients.items():
        if address != sender_address:  # Don't send message back to the sender
            try:
                encrypted_message = client_public_key.encrypt(
                    message.encode(),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                client_socket.send(encrypted_message)
            except Exception as e:
                print(f"[ERROR SENDING TO {address}] {e}")

def handle_client(client_socket, address):
    """ Handle communication with a connected client. """
    print(f"[NEW CONNECTION] {address} connected.")

    # Send server public key
    client_socket.send(public_pem)

    # Receive client public key
    client_pub_pem = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_pub_pem)

    # Store client info
    clients[address] = (client_socket, client_public_key)

    while True:
        try:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break

            # Decrypt the message
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()

            print(f"[{address}] {decrypted_message}")

            # Broadcast the message to all clients
            broadcast(address, f"{address}: {decrypted_message}")

        except Exception as e:
            print(f"[ERROR] {address}: {e}")
            break

    # Remove client on disconnect
    print(f"[DISCONNECTED] {address} left the chat.")
    del clients[address]
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    print("[SERVER STARTED] Listening on port 5555...")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

start_server()

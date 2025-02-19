import socket
import threading
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def receive_messages(client_socket, private_key):
    """ Continuously receive and decrypt messages from the server. """
    while True:
        try:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                print("\n[Disconnected from server]")
                break

            # Decrypt the received message
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Clear current input line and print the new message
            sys.stdout.write("\r" + " " * 80 + "\r")  # Clear line
            print(f"\n{decrypted_message.decode()}")
            sys.stdout.write("Enter message: ")  # Reprint input prompt
            sys.stdout.flush()

        except Exception as e:
            print(f"\n[ERROR] {e}")
            break

def client(serverIP):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((serverIP, 5555))

    # Receive server public key
    server_pub_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_pub_pem)

    # Send client public key
    client_socket.send(public_pem)

    # Start thread for receiving messages
    threading.Thread(target=receive_messages, args=(client_socket, private_key), daemon=True).start()

    while True:
        try:
            message = input("Enter message: ")

            if message.lower() == "exit":
                print("[Closing connection]")
                client_socket.close()
                break

            # Encrypt message with server's public key
            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            client_socket.send(encrypted_message)

        except Exception as e:
            print(f"\n[ERROR] {e}")
            client_socket.close()
            break

serverIP = input("Enter server IP: ")
client(serverIP)

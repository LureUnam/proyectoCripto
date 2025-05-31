# Server
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import socket
import json
import os
import time

demo_delay = 1.2  # segundos entre pasos

data_dir = "ra_data"
registry_path = os.path.join(data_dir, "registry.json")

with open(os.path.join(data_dir, "server_private.pem"), "rb") as f:
    server_private_key = RSA.import_key(f.read())

with open(registry_path, "r") as f:
    registry = json.load(f)

print("Registro de dispositivos cargado en el servidor.", flush=True)
time.sleep(demo_delay)

def handle_device(conn):
    try:
        device_id = conn.recv(1024).decode()
        print(f"[Servidor] Dispositivo conectado: {device_id}", flush=True)
        time.sleep(demo_delay)

        if device_id not in registry:
            print("[Servidor] Dispositivo no registrado.", flush=True)
            return

        device_entry = registry[device_id]
        device_pubkey = RSA.import_key(device_entry["public_key"].encode())

        encrypted_nonce = conn.recv(256)
        cipher_rsa_priv = PKCS1_OAEP.new(server_private_key)
        try:
            nonce = cipher_rsa_priv.decrypt(encrypted_nonce)
        except Exception as e:
            print("[Servidor] Error al descifrar el nonce.", e, flush=True)
            return

        cipher_rsa_pub = PKCS1_OAEP.new(device_pubkey)
        encrypted_response = cipher_rsa_pub.encrypt(nonce)
        conn.sendall(encrypted_response)
        print("[Servidor] Nonce verificado y reenviado.", flush=True)
        time.sleep(demo_delay)

        encrypted_session_key = conn.recv(256)
        session_key = cipher_rsa_priv.decrypt(encrypted_session_key)
        print("[Servidor] Clave de sesión recibida.", flush=True)
        time.sleep(demo_delay)

        iv = recv_exact(conn, 16)
        length_bytes = recv_exact(conn, 4)
        ciphertext_length = int.from_bytes(length_bytes, 'big')
        ciphertext = recv_exact(conn, ciphertext_length)
        received_hash = recv_exact(conn, 32)

        calculated_hash = hashlib.sha256(ciphertext).digest()
        if received_hash != calculated_hash:
            print("[Servidor] Advertencia: integridad comprometida.", flush=True)
            return
        print("[Servidor] Integridad del mensaje verificada.", flush=True)
        time.sleep(demo_delay)

        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        print(f"[Servidor] Mensaje recibido: {message.decode()}", flush=True)
        time.sleep(demo_delay)

        response = b"Hola dispositivo, soy el servidor."
        cipher_response = AES.new(session_key, AES.MODE_CBC)
        response_encrypted = cipher_response.encrypt(pad(response, AES.block_size))
        hash_response = hashlib.sha256(response_encrypted).digest()
        conn.sendall(cipher_response.iv)
        conn.sendall(response_encrypted)
        conn.sendall(hash_response)
        print("[Servidor] Respuesta enviada al dispositivo.", flush=True)
        time.sleep(demo_delay)

    except Exception as e:
        print(f"[Servidor] Error durante la comunicación: {e}", flush=True)
    finally:
        conn.close()

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

if __name__ == "__main__":
    print("[Servidor] Servidor iniciado y listo para conexiones.", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("localhost", 9090))
        server.listen()
        print("[Servidor] Esperando conexiones en puerto 9090...", flush=True)

        while True:
            conn, addr = server.accept()
            print(f"[Servidor] Conexión establecida desde {addr}", flush=True)
            handle_device(conn)

#Device
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import os
import socket
import time

# Ruta al registro exportado por la RA
data_dir = "ra_data"
registry_path = os.path.join(data_dir, "registry.json")

def load_device_credentials(device_id):
    with open(registry_path, "r") as f:
        registry = json.load(f)
        entry = registry.get(device_id)
        if not entry:
            raise Exception("Dispositivo no registrado")
        pubkey = RSA.import_key(entry["public_key"].encode())
        privkey = RSA.import_key(open(entry["private_key_path"], "rb").read())
        server_pubkey = RSA.import_key(open(entry["server_pub_path"], "rb").read())
        return pubkey, privkey, server_pubkey

def device_main(device_id):
    pub, priv, server_pub = load_device_credentials(device_id)
    print(f"[Dispositivo {device_id}] Claves cargadas.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", 9090))

        # Paso 1: Enviar ID del dispositivo
        s.sendall(device_id.encode())
        time.sleep(0.1)

        # Paso 2: Generar nonce y enviarlo cifrado con la clave pública del servidor
        nonce = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(server_pub)
        encrypted_nonce = cipher_rsa.encrypt(nonce)
        s.sendall(encrypted_nonce)
        print("[Dispositivo] Nonce enviado al servidor.")

        # Paso 3: Recibir el nonce de vuelta cifrado con la clave pública del dispositivo
        encrypted_response = s.recv(256)
        cipher_rsa_priv = PKCS1_OAEP.new(priv)
        response_nonce = cipher_rsa_priv.decrypt(encrypted_response)
        if response_nonce != nonce:
            print("[Dispositivo] Falló la autenticación del servidor.")
            return
        print("[Dispositivo] Autenticación mutua completada.")

        # Paso 4: Generar clave AES y enviarla cifrada con clave pública del servidor
        session_key = get_random_bytes(16)  # AES-128
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        s.sendall(encrypted_session_key)
        print("[Dispositivo] Clave de sesión enviada.")

        # Paso 5: Enviar mensaje cifrado con AES
        message = b"Hola servidor, soy el dispositivo."
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(message, AES.block_size))
        s.sendall(cipher_aes.iv + ciphertext)
        print("[Dispositivo] Mensaje enviado al servidor.")

        # Paso 6: Recibir respuesta cifrada
        iv_response = s.recv(16)
        encrypted_reply = s.recv(1024)
        cipher_response = AES.new(session_key, AES.MODE_CBC, iv_response)
        reply = unpad(cipher_response.decrypt(encrypted_reply), AES.block_size)
        print(f"[Dispositivo] Respuesta del servidor: {reply.decode()}")

if __name__ == "__main__":
    device_main("device1")

#Server
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import socket
import json
import os

# Ruta al registro exportado por la RA
data_dir = "ra_data"
registry_path = os.path.join(data_dir, "registry.json")

# Cargar clave privada del servidor
with open(os.path.join(data_dir, "server_private.pem"), "rb") as f:
    server_private_key = RSA.import_key(f.read())

# Cargar registro de dispositivos
with open(registry_path, "r") as f:
    registry = json.load(f)

print("Registro de dispositivos cargado en el servidor.")

def handle_device(conn):
    try:
        # Paso 1: Recibir ID del dispositivo
        device_id = conn.recv(1024).decode()
        print(f"[Servidor] Dispositivo conectado: {device_id}")

        if device_id not in registry:
            print("[Servidor] Dispositivo no registrado.")
            return

        device_entry = registry[device_id]
        device_pubkey = RSA.import_key(device_entry["public_key"].encode())

        # Paso 2: Recibir nonce cifrado
        encrypted_nonce = conn.recv(256)
        cipher_rsa_priv = PKCS1_OAEP.new(server_private_key)
        try:
            nonce = cipher_rsa_priv.decrypt(encrypted_nonce)
        except Exception as e:
            print("[Servidor] Error al descifrar el nonce.", e)
            return

        # Paso 3: Enviar el nonce de vuelta cifrado con clave pública del dispositivo
        cipher_rsa_pub = PKCS1_OAEP.new(device_pubkey)
        encrypted_response = cipher_rsa_pub.encrypt(nonce)
        conn.sendall(encrypted_response)
        print("[Servidor] Nonce verificado y reenviado.")

        # Paso 4: Recibir clave de sesión cifrada
        encrypted_session_key = conn.recv(256)
        session_key = cipher_rsa_priv.decrypt(encrypted_session_key)
        print("[Servidor] Clave de sesión recibida.")

        # Paso 5: Recibir mensaje cifrado con AES
        iv = conn.recv(16)
        ciphertext = conn.recv(1024)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        print(f"[Servidor] Mensaje recibido: {message.decode()}")

        # Paso 6: Enviar respuesta cifrada
        response = b"Hola dispositivo, soy el servidor."
        cipher_response = AES.new(session_key, AES.MODE_CBC)
        response_encrypted = cipher_response.encrypt(pad(response, AES.block_size))
        conn.sendall(cipher_response.iv + response_encrypted)
        print("[Servidor] Respuesta enviada al dispositivo.")

    except Exception as e:
        print(f"[Servidor] Error durante la comunicaci\u00f3n: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("localhost", 9090))
        server.listen()
        print("[Servidor] Esperando conexiones en puerto 9090...")

        while True:
            conn, addr = server.accept()
            print(f"[Servidor] Conexi\u00f3n establecida desde {addr}")
            handle_device(conn)

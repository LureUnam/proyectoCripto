#Server
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
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

        # Paso 5: Recibir mensaje cifrado
        iv = recv_exact(conn, 16)

        # Recibir longitud del ciphertext
        length_bytes = recv_exact(conn, 4)
        ciphertext_length = int.from_bytes(length_bytes, 'big')

        # Recibir ciphertext
        ciphertext = recv_exact(conn, ciphertext_length)

        # Recibir hash
        received_hash = recv_exact(conn, 32)

        # Verificar integridad del mensaje
        calculated_hash = hashlib.sha256(ciphertext).digest()
        if received_hash != calculated_hash:
            print("[Servidor] Advertencia: integridad comprometida.")
            return
        else:
            print("[Servidor] Integridad del mensaje verificada.")

        # Descifrar y mostrar mensaje
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        print(f"[Servidor] Mensaje recibido: {message.decode()}")

        # Paso 6: Enviar respuesta cifrada
        response = b"Hola dispositivo, soy el servidor."
        cipher_response = AES.new(session_key, AES.MODE_CBC)
        response_encrypted = cipher_response.encrypt(pad(response, AES.block_size))

        # Calcular hash del mensaje cifrado
        hash_response = hashlib.sha256(response_encrypted).digest()

        # Enviar IV + mensaje cifrado
        conn.sendall(cipher_response.iv)
        conn.sendall(response_encrypted)

        # Enviar hash
        conn.sendall(hash_response)
        print("[Servidor] Respuesta enviada al dispositivo.")

    except Exception as e:
        print(f"[Servidor] Error durante la comunicaci\u00f3n: {e}")
    finally:
        conn.close()
# Recibe exactamente 'n' bytes del socket, esperando si es necesario hasta completar la cantidad.       
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("localhost", 9090))
        server.listen()
        print("[Servidor] Esperando conexiones en puerto 9090...")

        while True:
            conn, addr = server.accept()
            print(f"[Servidor] Conexi\u00f3n establecida desde {addr}")
            handle_device(conn)

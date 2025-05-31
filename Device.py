#Device
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
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

        # Calcular hash del ciphertext
        hash_message = hashlib.sha256(ciphertext).digest()

        # Enviar IV (16 bytes)
        s.sendall(cipher_aes.iv)

        # Enviar longitud del ciphertext (4 bytes, entero codificado en big-endian)
        s.sendall(len(ciphertext).to_bytes(4, 'big'))

        # Enviar ciphertext
        s.sendall(ciphertext)

        # Enviar hash
        s.sendall(hash_message)
        print("[Dispositivo] Mensaje enviado al servidor.")

        # Paso 6: Recibir respuesta cifrada
        iv_response = s.recv(16)

        # Recibir mensaje cifrado y hash
        encrypted_reply = recv_exact(s, 48)  
        hash_received = recv_exact(s, 32)

        # Verificar integridad
        calculated_hash = hashlib.sha256(encrypted_reply).digest()
        if hash_received != calculated_hash:
            print("[Dispositivo] Advertencia: integridad de la respuesta comprometida.")
            return
        else:
            print("[Dispositivo] Integridad de la respuesta verificada.")

        # Descifrar y mostrar mensaje
        cipher_response = AES.new(session_key, AES.MODE_CBC, iv_response)
        reply = unpad(cipher_response.decrypt(encrypted_reply), AES.block_size)
        print(f"[Dispositivo] Respuesta del servidor: {reply.decode()}")

# Recibe exactamente 'n' bytes del socket, esperando si es necesario hasta completar la cantidad.  
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexión cerrada antes de recibir todos los datos")
        data += packet
    return data

if __name__ == "__main__":
    device_main("device1")



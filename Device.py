from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib 
import json
import os
import socket
import time

# Control de velocidad para la demostración
demo_delay = 1.2  # segundos entre pasos visibles

# Ruta donde se encuentra el registro con las claves de los dispositivos y servidor
data_dir = "ra_data"
registry_path = os.path.join(data_dir, "registry.json")

# Función para cargar las claves RSA del dispositivo y la clave pública del servidor desde el registro
def load_device_credentials(device_id):
    with open(registry_path, "r") as f:
        registry = json.load(f)
        entry = registry.get(device_id)  # Busca el dispositivo en el registro
        if not entry:
            raise Exception("Dispositivo no registrado")  # Error si no existe
        # Importa las claves públicas y privadas necesarias para la comunicación
        pubkey = RSA.import_key(entry["public_key"].encode())
        privkey = RSA.import_key(open(entry["private_key_path"], "rb").read())
        server_pubkey = RSA.import_key(open(entry["server_pub_path"], "rb").read())
        return pubkey, privkey, server_pubkey

# Función principal que maneja la comunicación segura con el servidor
def device_main(device_id):
    # Carga las claves necesarias para el dispositivo y el servidor
    pub, priv, server_pub = load_device_credentials(device_id)
    print(f"[Dispositivo {device_id}] Claves cargadas.", flush=True)
    time.sleep(demo_delay)

    # Crea un socket TCP para conectarse al servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", 9090))  # Conecta al servidor en localhost y puerto 9090

        # Paso 1: Enviar ID del dispositivo al servidor
        s.sendall(device_id.encode())
        time.sleep(0.1)  # Breve pausa

        # Paso 2: Generar un nonce (número aleatorio) y enviarlo cifrado con la clave pública del servidor
        nonce = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(server_pub)
        encrypted_nonce = cipher_rsa.encrypt(nonce)
        s.sendall(encrypted_nonce)
        print("[Dispositivo] Nonce enviado al servidor.", flush=True)
        time.sleep(demo_delay)

        # Paso 3: Recibir el nonce cifrado devuelto por el servidor y descifrarlo con la clave privada del dispositivo
        encrypted_response = s.recv(256)
        cipher_rsa_priv = PKCS1_OAEP.new(priv)
        response_nonce = cipher_rsa_priv.decrypt(encrypted_response)
        # Verifica que el nonce recibido coincida para confirmar autenticación mutua
        if response_nonce != nonce:
            print("[Dispositivo] Falló la autenticación del servidor.", flush=True)
            return
        print("[Dispositivo] Autenticación mutua completada.", flush=True)
        time.sleep(demo_delay)

        # Paso 4: Generar la clave AES para la sesión y enviarla cifrada con la clave pública del servidor
        session_key = get_random_bytes(16)  # AES-128 bits
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        s.sendall(encrypted_session_key)
        print("[Dispositivo] Clave de sesión enviada.", flush=True)
        time.sleep(demo_delay)

        # Paso 5: Enviar un mensaje cifrado con AES usando la clave de sesión
        message = b"Hola servidor, soy el dispositivo."
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(message, AES.block_size))
        # Calcular hash SHA-256 para verificar integridad del mensaje
        hash_message = hashlib.sha256(ciphertext).digest()

        # Enviar IV, longitud del mensaje cifrado, mensaje cifrado y hash al servidor
        s.sendall(cipher_aes.iv)
        s.sendall(len(ciphertext).to_bytes(4, 'big'))
        s.sendall(ciphertext)
        s.sendall(hash_message)
        print("[Dispositivo] Mensaje enviado al servidor.", flush=True)
        time.sleep(demo_delay)

        # Paso 6: Recibir la respuesta cifrada del servidor
        iv_response = s.recv(16)
        encrypted_reply = recv_exact(s, 48)
        hash_received = recv_exact(s, 32)

        # Verificar la integridad del mensaje recibido comparando hashes
        calculated_hash = hashlib.sha256(encrypted_reply).digest()
        if hash_received != calculated_hash:
            print("[Dispositivo] Advertencia: integridad de la respuesta comprometida.", flush=True)
            return
        print("[Dispositivo] Integridad de la respuesta verificada.", flush=True)
        time.sleep(demo_delay)

        # Descifrar el mensaje usando la clave AES y mostrarlo
        cipher_response = AES.new(session_key, AES.MODE_CBC, iv_response)
        reply = unpad(cipher_response.decrypt(encrypted_reply), AES.block_size)
        print(f"[Dispositivo] Respuesta del servidor: {reply.decode()}", flush=True)
        time.sleep(demo_delay)

# Función auxiliar para recibir exactamente n bytes desde el socket (bloqueante)
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexión cerrada antes de recibir todos los datos")
        data += packet
    return data

# Punto de entrada al ejecutar el script directamente
if __name__ == "__main__":
    device_main("device1")

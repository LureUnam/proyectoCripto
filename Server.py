from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import os
import socket

# Ruta al registro exportado por la RA
data_dir = "ra_data"
registry_path = os.path.join(data_dir, "registry.json")

class Server:
    def __init__(self):
        self.device_registry = {}
        self.load_registry()

        # Generar par de claves del servidor (o cargar si ya existen)
        self.server_key_path = os.path.join(data_dir, "server_priv.pem")
        self.server_pub_path = os.path.join(data_dir, "server_pub.pem")

        if os.path.exists(self.server_key_path) and os.path.exists(self.server_pub_path):
            with open(self.server_key_path, "rb") as f:
                self.private_key = RSA.import_key(f.read())
            with open(self.server_pub_path, "rb") as f:
                self.public_key = RSA.import_key(f.read())
        else:
            key = RSA.generate(2048)
            self.private_key = key
            self.public_key = key.publickey()
            with open(self.server_key_path, "wb") as f:
                f.write(self.private_key.export_key())
            with open(self.server_pub_path, "wb") as f:
                f.write(self.public_key.export_key())

    def load_registry(self):
        with open(registry_path, "r") as f:
            self.device_registry = json.load(f)
        print("Registro de dispositivos cargado en el servidor.")

    def get_device_public_key(self, device_id):
        entry = self.device_registry.get(device_id)
        if entry:
            return RSA.import_key(entry["public_key"].encode())
        return None

    def start_server(self):
        print("[Servidor] Esperando conexiones en puerto 9090...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("localhost", 9090))
            s.listen(1)
            conn, addr = s.accept()
            with conn:
                print(f"[Servidor] Conexión establecida desde {addr}")
                # Paso 1: Recibir ID del dispositivo
                device_id = conn.recv(64).decode()
                print(f"[Servidor] Dispositivo conectado: {device_id}")
                device_pubkey = self.get_device_public_key(device_id)
                if not device_pubkey:
                    print("[Servidor] Dispositivo no registrado.")
                    return

                # Paso 2: Recibir nonce cifrado
                encrypted_nonce = conn.recv(256)
                cipher_rsa = PKCS1_OAEP.new(self.private_key)
                try:
                    device_nonce = cipher_rsa.decrypt(encrypted_nonce)
                    print("[Servidor] Nonce recibido y descifrado.")
                except Exception as e:
                    print("[Servidor] Error al descifrar el nonce.")
                    return

                # Paso 3: Enviar el mismo nonce cifrado con la clave pública del dispositivo
                cipher_reply = PKCS1_OAEP.new(device_pubkey)
                encrypted_response = cipher_reply.encrypt(device_nonce)
                conn.sendall(encrypted_response)
                print("[Servidor] Nonce reenviado al dispositivo.")

if __name__ == "__main__":
    server = Server()
    server.start_server()

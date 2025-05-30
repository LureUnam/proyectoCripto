from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
import os

# Ruta donde están las claves generadas por la RA
data_dir = "ra_data"

class Device:
    def __init__(self, device_id):
        self.device_id = device_id
        self.priv_key_path = os.path.join(data_dir, f"{device_id}_priv.pem")
        self.pub_key_path = os.path.join(data_dir, f"{device_id}_pub.pem")
        self.server_pub_path = os.path.join(data_dir, "server_pub.pem")

        # Cargar claves del dispositivo
        with open(self.priv_key_path, "rb") as f:
            self.private_key = RSA.import_key(f.read())
        with open(self.pub_key_path, "rb") as f:
            self.public_key = RSA.import_key(f.read())

        # Cargar clave pública del servidor
        with open(self.server_pub_path, "rb") as f:
            self.server_public_key = RSA.import_key(f.read())

    def mutual_authentication(self):
        print(f"\n[{self.device_id}] Iniciando autenticación mutua con el servidor...")

        # Paso 1: Conectar al servidor
        with socket.create_connection(("localhost", 9090)) as sock:
            # Paso 2: Enviar ID del dispositivo
            sock.sendall(self.device_id.encode())

            # Paso 3: Generar y enviar nonce cifrado con clave pública del servidor
            device_nonce = os.urandom(16)
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_nonce = cipher_rsa.encrypt(device_nonce)
            sock.sendall(encrypted_nonce)
            print(f"[{self.device_id}] Nonce enviado al servidor.")

            # Paso 4: Recibir el mismo nonce cifrado con la clave privada del servidor (autenticación mutua)
            received_encrypted_nonce = sock.recv(256)  # tamaño para RSA 2048
            cipher_rsa_client = PKCS1_OAEP.new(self.private_key)
            decrypted_nonce = cipher_rsa_client.decrypt(received_encrypted_nonce)

            if decrypted_nonce == device_nonce:
                print(f"[{self.device_id}] Autenticación mutua exitosa.")
            else:
                print(f"[{self.device_id}] Falló la autenticación del servidor.")

if __name__ == "__main__":
    device = Device("device_001")
    device.mutual_authentication()

# RA
import os
import json
from Crypto.PublicKey import RSA

# Carpeta donde se almacenarán las claves y el registro
data_dir = "ra_data"
os.makedirs(data_dir, exist_ok=True)  # Crear carpeta si no existe
registry_path = os.path.join(data_dir, "registry.json")  # Ruta del archivo JSON con registro

# Función para generar un par de claves RSA para un dispositivo específico
def generate_device(device_id):
    # Genera un par de claves RSA de 2048 bits
    key = RSA.generate(2048)
    # Define las rutas donde se guardarán las claves privada y pública
    priv_key_path = os.path.join(data_dir, f"{device_id}_private.pem")
    pub_key_path = os.path.join(data_dir, f"{device_id}_public.pem")
    # Guarda la clave privada en formato PEM
    with open(priv_key_path, "wb") as f:
        f.write(key.export_key())
    # Guarda la clave pública en formato PEM
    with open(pub_key_path, "wb") as f:
        f.write(key.publickey().export_key())

    # Carga el registro actual de dispositivos, o crea uno nuevo si no existe
    if os.path.exists(registry_path):
        with open(registry_path, "r") as f:
            registry = json.load(f)
    else:
        registry = {}

    # Añade la información del dispositivo al registro
    registry[device_id] = {
        "public_key": key.publickey().export_key().decode(),  # Clave pública en texto
        "private_key_path": priv_key_path,                    # Ruta clave privada
        "server_pub_path": os.path.join(data_dir, "server_public.pem")  # Ruta clave pública servidor
    }

    # Guarda el registro actualizado en formato JSON con indentación para legibilidad
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=4)

# Función para generar las claves RSA del servidor
def generate_server():
    # Genera un par de claves RSA de 2048 bits para el servidor
    key = RSA.generate(2048)
    # Guarda la clave privada del servidor
    with open(os.path.join(data_dir, "server_private.pem"), "wb") as f:
        f.write(key.export_key())
    # Guarda la clave pública del servidor
    with open(os.path.join(data_dir, "server_public.pem"), "wb") as f:
        f.write(key.publickey().export_key())

# Cuando se ejecuta el script directamente, genera claves del servidor y del dispositivo "device1"
if __name__ == "__main__":
    generate_server()
    generate_device("device1")

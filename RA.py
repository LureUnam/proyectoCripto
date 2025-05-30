import os
import json
from Crypto.PublicKey import RSA

data_dir = "ra_data"
os.makedirs(data_dir, exist_ok=True)
registry_path = os.path.join(data_dir, "registry.json")

def generate_device(device_id):
    # Generar par de claves del dispositivo
    key = RSA.generate(2048)
    priv_key_path = os.path.join(data_dir, f"{device_id}_private.pem")
    pub_key_path = os.path.join(data_dir, f"{device_id}_public.pem")
    with open(priv_key_path, "wb") as f:
        f.write(key.export_key())
    with open(pub_key_path, "wb") as f:
        f.write(key.publickey().export_key())

    # Registrar dispositivo
    if os.path.exists(registry_path):
        with open(registry_path, "r") as f:
            registry = json.load(f)
    else:
        registry = {}

    registry[device_id] = {
        "public_key": key.publickey().export_key().decode(),
        "private_key_path": priv_key_path,
        "server_pub_path": os.path.join(data_dir, "server_public.pem")
    }

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=4)

def generate_server():
    # Generar clave pública del servidor
    key = RSA.generate(2048)
    with open(os.path.join(data_dir, "server_private.pem"), "wb") as f:
        f.write(key.export_key())
    with open(os.path.join(data_dir, "server_public.pem"), "wb") as f:
        f.write(key.publickey().export_key())

if __name__ == "__main__":
    generate_server()
    generate_device("device1")

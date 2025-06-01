from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import asyncio
import subprocess
import json
import sys
import traceback

# Creamos la instancia de la aplicación FastAPI
app = FastAPI()

# Variable global para almacenar la referencia al proceso del servidor
server_process = None

# Ruta raíz que sirve el archivo HTML de la interfaz web
@app.get("/")
async def index():
    # Abrimos y leemos el archivo 'protocolo.html' y lo enviamos como respuesta HTML
    with open("protocolo.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

# Endpoint para generar claves RSA ejecutando RA.py
@app.post("/generate-keys")
async def generate_keys():
    try:
        # Ejecutamos el script RA.py de forma asíncrona y capturamos su salida y errores
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "RA.py", # Ejecutamos con el intérprete actual de Python
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Esperamos que el proceso termine y obtenemos stdout y stderr
        stdout, stderr = await proc.communicate()
        # Decodificamos la salida y errores manejando posibles caracteres especiales
        stdout_text = stdout.decode("cp1252", errors="ignore").strip()
        stderr_text = stderr.decode("cp1252", errors="ignore").strip()
        # Si el proceso terminó correctamente, devolvemos la salida como mensaje
        if proc.returncode == 0:
            return JSONResponse(content={"message": stdout_text or "Claves generadas correctamente."})
        else:
            # Si hubo error, devolvemos el mensaje de error con código 500
            return JSONResponse(content={"message": f"Error al generar claves:\n{stderr_text}"}, status_code=500)
    except Exception:
        # En caso de excepción, devolvemos el traceback para diagnóstico
        return JSONResponse(content={"message": f"Excepción:\n{traceback.format_exc()}"}, status_code=500)

# WebSocket para iniciar y monitorear el servidor (Server.py)
@app.websocket("/ws-server")
async def websocket_server(ws: WebSocket):
    await ws.accept() # Aceptamos la conexión WebSocket entrante
    global server_process

    # Lanzamos el proceso Server.py como subproceso para capturar su salida en tiempo real
    server_process = subprocess.Popen(
        [sys.executable, "Server.py"], # Ejecutamos con el intérprete Python actual
        stdout=subprocess.PIPE, # Capturamos salida estándar
        stderr=subprocess.STDOUT, # Unificamos errores con salida estándar
        bufsize=1, # Buffer lineal para lectura línea a línea
        universal_newlines=True # Decodificación automática a str
    )

    # Función asíncrona para leer línea a línea la salida del proceso y enviarla al cliente
    async def stream_output(proc, source):
        try:
            while True:
                # Leemos una línea de salida del proceso en un hilo separado para no bloquear el event loop
                line = await asyncio.get_event_loop().run_in_executor(None, proc.stdout.readline)
                if not line:
                    break # Fin de la salida
                # Enviamos la línea leída codificada en JSON, indicando la fuente 'server'
                await ws.send_text(json.dumps({"source": source, "message": line.rstrip()}))
        except WebSocketDisconnect:
            # Si el WebSocket se cierra, terminamos el proceso si sigue activo
            if proc.poll() is None:
                proc.terminate()

    # Ejecutamos la función que envía la salida al cliente
    await stream_output(server_process, "server")

# Endpoint para detener el proceso Server.py y liberar recursos
@app.post("/stop-server")
async def stop_server():
    global server_process
    # Verificamos que el proceso esté activo antes de detenerlo
    if server_process and server_process.poll() is None:
        server_process.terminate() # Terminamos el proceso
        server_process.wait() # Esperamos a que finalice correctamente
        return JSONResponse(content={"message": "Servidor detenido correctamente."})
    # Si no estaba activo, informamos que no había servidor activo
    return JSONResponse(content={"message": "Servidor no estaba activo."})

# WebSocket para iniciar y monitorear el dispositivo (Device.py)
@app.websocket("/ws-device")
async def websocket_device(ws: WebSocket):
    await ws.accept() # Aceptamos conexión WebSocket entrante

    # Lanzamos el proceso Device.py como subproceso para capturar su salida en tiempo real
    device_proc = subprocess.Popen(
        [sys.executable, "Device.py"], # Ejecutamos con intérprete Python actual
        stdout=subprocess.PIPE, # Capturamos salida estándar
        stderr=subprocess.STDOUT, # Unificamos errores con salida estándar
        bufsize=1, # Buffer lineal para lectura línea a línea
        universal_newlines=True # Decodificación automática a str
    )

    # Función asíncrona para leer la salida del proceso y enviarla al cliente
    async def stream_output(proc, source):
        try:
            while True:
                line = await asyncio.get_event_loop().run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                await ws.send_text(json.dumps({"source": source, "message": line.rstrip()}))
        except WebSocketDisconnect:
            # Si el WebSocket se cierra, terminamos el proceso
            proc.terminate()

    # Ejecutamos la función que envía la salida al cliente
    await stream_output(device_proc, "device")
    # Terminamos el proceso cuando se completa la transmisión
    device_proc.terminate()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import asyncio
import subprocess
import json
import sys
import traceback

app = FastAPI()
server_process = None

@app.get("/")
async def index():
    with open("protocolo.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/generate-keys")
async def generate_keys():
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "RA.py",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        stdout_text = stdout.decode("cp1252", errors="ignore").strip()
        stderr_text = stderr.decode("cp1252", errors="ignore").strip()
        if proc.returncode == 0:
            return JSONResponse(content={"message": stdout_text or "Claves generadas correctamente."})
        else:
            return JSONResponse(content={"message": f"Error al generar claves:\n{stderr_text}"}, status_code=500)
    except Exception:
        return JSONResponse(content={"message": f"Excepción:\n{traceback.format_exc()}"}, status_code=500)

@app.websocket("/ws-server")
async def websocket_server(ws: WebSocket):
    await ws.accept()
    global server_process

    server_process = subprocess.Popen(
        [sys.executable, "Server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True
    )

    async def stream_output(proc, source):
        try:
            while True:
                line = await asyncio.get_event_loop().run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                await ws.send_text(json.dumps({"source": source, "message": line.rstrip()}))
        except WebSocketDisconnect:
            if proc.poll() is None:
                proc.terminate()

    await stream_output(server_process, "server")

@app.post("/stop-server")
async def stop_server():
    global server_process
    if server_process and server_process.poll() is None:
        server_process.terminate()
        server_process.wait()
        return JSONResponse(content={"message": "Servidor detenido correctamente."})
    return JSONResponse(content={"message": "Servidor no estaba activo."})

@app.websocket("/ws-device")
async def websocket_device(ws: WebSocket):
    await ws.accept()

    device_proc = subprocess.Popen(
        [sys.executable, "Device.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True
    )

    async def stream_output(proc, source):
        try:
            while True:
                line = await asyncio.get_event_loop().run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                await ws.send_text(json.dumps({"source": source, "message": line.rstrip()}))
        except WebSocketDisconnect:
            proc.terminate()

    await stream_output(device_proc, "device")
    device_proc.terminate()

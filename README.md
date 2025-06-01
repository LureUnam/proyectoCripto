- Domínguez Morales Héctor Enrique
- González Rico Martín
- Yañez García Fernando

## En la carpeta del proyecto: 
-tener python 3.13+

-instalar dependencias con 'pip install fastapi uvicorn pycryptodome websockets'

## Para correr el proyecto:
- en terminal: 'python -m uvicorn web:app'.

- abrir navegador en 'http://127.0.0.1:8000'.

## Guía de uso:
1. Generar claves con botón rojo, esperar mensaje de confirmación.
2. Iniciar servidor, esperar mensaje '[Servidor] Esperando conexiones en puerto 9090...'.
3. Iniciar dispositivo y observar comunicación.
4. Detener dispositivo.
5. Detener servidor (Finaliza servidor y se libera el puerto).

Puedes volver a probar en la misma página siguiendo los mismos pasos.

# Nota
- Asegurarse de que los puertos 8000 y 9090 estén libres.
- Siempre detener servidor y dispositivo, recargar la página sin detener el servidor puede causar errores.
- En caso de error cerrar la terminal y volver a correr el proyecto
- El programa igualmente puede ser visto desde 2 consolas distintas, en una corremos RA.py y posteriormente Server.py, y en la otra consola corremos Device.py y observamos la comunicación.

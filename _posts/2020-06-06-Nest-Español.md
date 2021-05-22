---
title: HTB Nest Write-up (Español)
tags: [HackTheBox, Windows]
image: /assets/images/Nest/1__3ANISohoQRDGlDiHTsHrwg.jpeg
published: true
banner: true
---

I cloned my writeup that was originally posted on [medium](https://medium.com/@5ubterranean/htb-nest-write-up-espa%C3%B1ol-ae4cc92a7a4f)

Nest es una máquina basada en Windows que estuvo activa desde el 25 de enero del 2020 hasta el 6 de Junio, a pesar de estar calificada como “fácil” es una máquina bastante “enredada”, en esta máquina no obtendremos una shell hasta el final, así que solo interactuaremos con ella a través de las carpetas compartidas y un servicio llamado “HQK reporting service”, conseguiremos nuestras primeras credenciales por un archivo disponible en una de las carpetas compartidas sin necesidad de credenciales, con este usuario encontraremos otras credenciales, pero ahora encriptadas, encontraremos un proyecto de Visual Studio el cual fue usado para encriptar las credenciales así que tendremos que leerlo y usarlo para desencriptarlas, luego con este usuario encontraremos un programa escrito en C# y un archivo vacío, pero de hecho este tiene información en alternate data streams, por lo que necesitaremos una máquina Windows para acceder a ella, allí encontraremos una contraseña que nos servirá para activar el “Debug mode” en el servidor HQK, con está capacidad encontraremos la contraseña de Administrator pero una vez más, encriptada, en este caso tendremos de descompilar el programa de C#, encontrar la función de desencriptación y usarla, y con eso habremos acabado con la máquina.

# Enumeración

Empezamos usando masscan para encontrar todos los puertos disponibles y luego usamos nmap para conseguir más información de los mismos.

```bash
masscan -e tun0 — rate=500 -p 0–65535 10.10.10.178  
nmap -sC -sV -p 445,4386 -Pn -o scan.txt 10.10.10.178

PORT     STATE SERVICE       VERSION  
445/tcp  open  microsoft-ds?  
4386/tcp open  unknown  
| fingerprint-strings:   
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:   
|     Reporting Service V1.2  
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions:   
|     Reporting Service V1.2  
|     Unrecognised command  
|   Help:   
|     Reporting Service V1.2  
|     This service allows users to run queries against databases using the legacy HQK format  
|     AVAILABLE COMMANDS ---  
|     LIST  
|     SETDIR <Directory\_Name>  
|     RUNQUERY <Query\_ID>  
|     DEBUG <Password>  
|\_    HELP <Command>
```

Ya que tenemos el servicio de SMB (puerto 445) abierto usamos `smbclient` para ver qué carpetas está disponibles, `smbclient -L \\10.10.10.178`.

![](/assets/images/Nest/1__m9GXVaH__nNdIbHD1drk1og.png)


# Primer usuario

Conseguimos nuestro primer usuario a través de la carpeta “Data”, si bien podemos navegar por esta usando `smbclient` yo prefiero montar las carpetas, primero creo un direcotrio “share” y luego lo monto ahí: `mount -t cifs \\\\10.10.10.178\\Data share`.  
Y ahora que está montada podemos usar `tree` para explorar su contenido, el argumento “f” hace que imprima toda la ruta hacia el archivo (así puedo copiar y pegar la ruta para interactuar con él de forma más sencilla), “a” para ver archivos ocultos y “s” para ver el tamaño, `tree -fas share/`.

![](/assets/images/Nest/1__4kPO2r9fKT1dTA__F8HyIMA.png)


Tenemos dos archivos, revisamos “Welcome Email.txt”.

![](/assets/images/Nest/1__2C5Av6F4WnwGVjBEKjuf6g.png)


Y encontramos la credenciales para nuestro primer usuario, TempUser,  
welcome2019.

# Segundo usuario

Empezamos revisando a qué carpetas podemos acceder con este usuario usando crackmapexec: `cme smb 10.10.10.178 -u TempUser -p welcome2019 — shares`.

![](/assets/images/Nest/1__PcFTwgmsjw1u5IwVxvtgWA.png)


Volvemos a revisar “Data” pero con este nuevo usuario: `mount -t cifs -o user="TempUser" \\\\10.10.10.178\\Data share`, y una vez más usamos `tree`.

![](/assets/images/Nest/1__3uzikyf5__vABM49__XDRE0w.png)


Tenemos acceso a algunos archivos nuevos, aunque de estos 2 son los que nos importan, primero revisamos “RU\_config.xml”.

![](/assets/images/Nest/1__9Uip__D__Xvugoik1a5iJI2Q.png)


Encontramos un nuevo usuario y contraseña, esta parece estar codificada en base64, pero aunque la decodifiquemos no obtendremos nada legible, por lo que tendremos que seguir revisando los archivos, nuestra siguiente pista la encontraremos al final del archivo “config.xml” dentro de “Notepadplusplus”.

![](/assets/images/Nest/1__J40EkgeF65168l1SzOZwtg.png)


Ahí vemos una ruta a una carpeta compartida “\\\\HTB-NEST\\Secure$\\IT\\Carl\\Temp.txt”. Procedemos a montar “Secure$” a ver si encontramos algo, `mount -t cifs -o username="TempUser" \\\\10.10.10.178\\Secure$ share`, y de nuevo usamos tree.

![](/assets/images/Nest/1__A11fMzbLGEyEw9xJbR6F5w.png)


Y… no vemos nada, pero el archivo nos decía que había un directorio llamado “Carl” en “IT”, ¿qué tal si intentamos listar “share/IT/Carl”?

![](/assets/images/Nest/1__xN8JSNNr3SNCcGUwsnVcvw.png)


Sí tenemos carpetas, esto se debe a que no tenemos permisos para listar los archivos dentro de IT, pero eso no significa que no tengamos los permisos para entrar al mismo, pero para ello tendríamos que saber el nombre de la carpeta a la cual queremos entrar, muy bien volvemos a usar `tree` para ver que hay aquí.

![](/assets/images/Nest/1__ri__2I9xICE__6FfWme3JYHA.png)


Tenemos varios archivos dentro la carpeta “VB Projects”, y estos no son más que un proyecto de Visual Basic en Visual Studio, así que los copiamos a una máquina Windows y abrimos el proyecto en Visual Studio para poder tener todo de manera más ordenada, luego de observar el proyecto el archivo que nos importa es “Utils.vb”.

![](/assets/images/Nest/1__mfgTm__ZLi1WYA__a2kRk__qg.png)


Este archivo tiene unas funciones “EncryptString” y “DecryptString”, la que nos interesa es la de decrypt ya que tenemos la contraseña encriptada.

![](/assets/images/Nest/1__2gZh3Z__lyWH__KEOx0oa3aw.png)


Al menos yo nunca he trabajado con proyectos de Visual Studio, por lo que arreglarlo para que funcione me tomaría demasiado tiempo, así que opté por algo más sencillo, utilicé la página [https://dotnetfiddle.net/](https://dotnetfiddle.net/) para copiar y pegar los pedazos de código que quería, hacerle unas modificaciones y desencriptar la contraseña (el código se hace algo largo así que no lo pongo).

![](/assets/images/Nest/1____I6UAiCMRt4N7sg6ktcBJg.png)


Luego de ejecutar el programa obtenemos que la contraseña es “xRxRxPANCAK3SxRxRx”.

# Acceso a administrator

Ahora con este nuevo usuario montamos la carpeta “Users”, `mount -t cifs -o username="c.smith" \\\\10.10.10.178\\Users share`, y revisamos con `tree`.

![](/assets/images/Nest/1__HIAtZadzB2sZohHPkYEPvQ.png)


Como vemos aquí encontramos el archivo “user.txt”, y los demás archivos tienen que ver con algo llamado “HQK”, pero ¿qué es eso?, regresamos a nuestro escaneo de puertos, este nos dijo que el puerto 4386 también estaba abierto, nos conectamos a este usando `telnet` (nc tiene problemas con este servicio).

![](/assets/images/Nest/1__XPNxIcypx6TqQ5iVISJzVg.png)


Vemos que es un servicio que nos da cierta interacción con los archivos internos de la máquina, y parece tener un modo de debug, el cual nos debería dar unas funciones extra. Entre los archivos que encontramos estaba “Debug Mode Password.txt”, pero este está vacío, aun así este nos puede llevar a cierta información a través de Aternate Data Streams (o [Flujos Alternativos de Datos](https://es.wikipedia.org/wiki/Alternate_Data_Streams) en español), pero para acceder a esta información necesitaremos una vez más de una máquina con Windows. Para que la máquina Windows pueda acceder a la máquina de HTB tenemos que routear el tráfico a través de nuestra máquina con Linux, para esto seguimos las instrucciones de un [script](https://github.com/juliourena/plaintext/blob/master/hackthebox/ConnWin-KaliVPN.sh) creado por [Julio Ureña](https://www.youtube.com/channel/UC2o1vzpUIvgf0VMJIMKZ_rQ) para este propósito, todo lo que tenemos que hacer el habilitar el port forawarnding en nuestra máquina Linux (si han tratado de hacer ataques MiTM esto les resultará familiar).

```bash
iptables --table nat --append POSTROUTING --out-interface tun0 -j MASQUERADE  
echo 1 > /proc/sys/net/ipv4/ip\_forward
```

Y luego agregamos la ruta a Windows con el comando: `route add 10.10.10.0 mask 255.255.255.0 192.168.56.109`. Aquí si cometemos el error de acceder a “\\\\10.10.10.178\\Users” directamente no podremos acceder a la carpeta c.smith ya que estaremos logueados como invitado ya que no introducimos ningunas credenciales.

![](/assets/images/Nest/1__7ZwNvnqLWT7SkLqB71775g.png)


Volvemos a un cmd y borramos la carpeta compartida de las rutas guardadas por Windows, para esto usamos: `net use \\10.10.10.178\Users /delete`.  
Ahora montamos de nuevo la carpeta pero ahora introduciendo las credenciales correspondientes, en este caso lo montamos a una unidad “T:”, esto no es necesario pero prefiero hacerlo así: `net use T: \\10.10.10.178\Users /u:HTB-NEST\c.smith xRxRxPANCAK3SxRxRx`, ahora sí podemos acceder a la carpeta.

![](/assets/images/Nest/1__1JjB5ib__HVW4ad0JNHWKBw.png)


Pero para poder obtener la información que queremos tenemos que usar el cmd, una vez en la carpeta usamos el comando `dir /r`, como se ve, si solo usamos `dir` no obtendremos la información que queremos.

![](/assets/images/Nest/1__GHWgrGePBBIOkflkhl86cQ.png)


Para conseguir la información usamos el comando: `more < “Debug Mode Password.txt:Password:$DATA”`.

![](/assets/images/Nest/1__Iax7KT1MyuFGwtaBJvrKnA.png)


Y conseguimos la contraseña para desbloque el Debug Mode, WBQ201953D8w. Regresamos a nuestra máquina Linux, nos conectamos al puerto 4386 y activamos el Debug Mode.

![](/assets/images/Nest/1__J12WsmNAMZjOj4mLckb98g.png)


Tenemos dos nuevos comandos, pero el importante es “SHOWQUERY” que nos permitirá leer archivos, subimos un directorio y entramos a “LDAP”, ahí encontramos el archivo “Ldap.conf”.

![](/assets/images/Nest/1__ewdCdZhJOWQhEWPNaD7sBw.png)


Al leerlo encontramos la contraseña del usuario “Administrator”, pero una vez más está encriptada.

![](/assets/images/Nest/1__p8__gcWS2wwuuJAY__ObWuYQ.png)


Al lado de este archivo estaba “HqkLdap.exe”, pero al ser un ejecutable no podemos leerlo, pero luego de pensar por un rato recordamos que ya hemos visto ese archivo, este se encontraba en la carpeta “Users”, ya que aún lo tenemos montado revisamos qué tipo de archivo es.

![](/assets/images/Nest/1__XYAX5lQXGZno0L6iIcXbcA.png)


Bueno es un archivo .Net, en búsqueda de un descompilador para .Net nos encontramos con [dotPeek](https://www.jetbrains.com/es-es/decompiler/), muy bien, una vez más vamos a Windows, luego de revisar el código vemos que lo que nos interesa está en HqkLdap/CR.

![](/assets/images/Nest/1__MZyqv9HahktrzC3hPvh8BQ.png)


En este caso tenemos código en C#, por suerte dotnetfiddle también puede manejarlo, así que regresamo ahí y copiamos las partes de código que nos interesan, resultando en el programa:

```C#
using System;  
using System.IO;  
using System.Security.Cryptography;  
using System.Text;  
       
public class CR  
{  
 private const string K = "667912";  
    private const string I = "1L1SA61493DRV53Z";  
    private const string SA = "1313Rf99";

public static string DS(string EncryptedString)  
    {  
      return string.IsNullOrEmpty(EncryptedString) ? string.Empty : CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);  
    }  
 private static string RD(  
      string cipherText,  
      string passPhrase,  
      string saltValue,  
      int passwordIterations,  
      string initVector,  
      int keySize)  
    {  
      byte\[\] bytes1 = Encoding.ASCII.GetBytes(initVector);  
      byte\[\] bytes2 = Encoding.ASCII.GetBytes(saltValue);  
      byte\[\] buffer = Convert.FromBase64String(cipherText);  
      byte\[\] bytes3 = new Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations).GetBytes(checked ((int) Math.Round(unchecked ((double) keySize / 8.0))));  
      AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider();  
      cryptoServiceProvider.Mode = CipherMode.CBC;  
      ICryptoTransform decryptor = cryptoServiceProvider.CreateDecryptor(bytes3, bytes1);  
      MemoryStream memoryStream = new MemoryStream(buffer);  
      CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read);  
      byte\[\] numArray = new byte\[checked (buffer.Length + 1)\];  
      int count = cryptoStream.Read(numArray, 0, numArray.Length);  
      memoryStream.Close();  
      cryptoStream.Close();  
      return Encoding.ASCII.GetString(numArray, 0, count);  
    }  
 public static void Main()  
 {  
  Console.WriteLine(DS("yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="));  
 }  
}
```


Y al ejecutarlos no obtenemos la contraseña.

![](/assets/images/Nest/1__lX0lX68Pys65M5aSeqUNsw.png)


Utilizamos crackmapexec para comprobar que esta sea correcta: `cme smb 10.10.10.178 -u "Administrator" -p "XtH4nkS4Pl4y1nGX" --shares`.

![](/assets/images/Nest/1__HO0nvuquQaPoks4DwAA9jw.png)


Nos devuelve el mensaje “Pwn3d!”, por lo que podemos conseguir una shell, para esto utilizamos psexec de la herramientas de Impacket: `python3 psexec.py Administrator:XtH4nkS4Pl4y1nGX@10.10.10.178`.

![](/assets/images/Nest/1__qNZ1tdoOa7EtPAqk06VPyQ.png)


Y lo logramos, somos nt authority, y tenemos acceso al archivo root.txt, para estar marcada como fácil fue una máquina que tomó bastante tiempo, si bien los pasos no fueron demasiado complicados encontrar qué había que hacer tomó una buena cantidad de tiempo.

### Descargo de responsabilidad

Todos los recursos brindados en este post se hicieron puramente con fines educativos y de concientización, el autor no se hace responsable por las acciones que las personas puedan realizar con el contenido del mismo.
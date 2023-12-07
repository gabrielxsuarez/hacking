Introducción a Linux
====================

Introducción
============

### Bienvenido/a al curso

### Sistemas operativos para pentesting
 - Parrot OS
 - Kali Linux
 - Arch Linux

### Creando una nueva máquina virtual
 - VMWare Workstation
 - Network Bridge
 - grub: linux - rw init=/bin/bash; ip a; vi /etc/network/interfaces

### Instalación del sistema operativo
 - Cifar Sistema

Temario
=======

### Comandos básicos de Linux [1-2]
 - Comandos: whoami, id, sudo, cat, which, echo, grep
 - Archivos: /etc/group
 - Variables de entorno: $PATH
 - Flujos: pipe
 - Atajos: ctrl+l

### Comandos básicos de Linux [2-2]
 - Comandos: command, ls, cd, pwd
 - Archivos: /etc/passwd, /etc/shells
 - Variables de entorno: $HOME, $SHELL
 - Atajos: tab

### Control del flujo stderr-stdout, operadores y procesos en segundo plano
 - Archivos: /dev/null
 - Flujos: && || ; $? 2> &> & disown
 - Conceptos: pid

### Descriptores de archivo
 - Comandos: exec
 - Descriptor: <> <{lectura} >{escritura} >&-

### Cuestionario de control de flujo y operadores

### Lectura e interpretación de permisos [1-2]
 - Comandos: rm, nano, vi, touch
 - Flujos: >>

### Lectura e interpretación de permisos [2-2]
 - Archivos: /etc/shadow, /etc/login.defs

### Asignación de permisos [1-2]
 - Comandos: mkdir, exit, chmod, chgrp

### Asignación de permisos [2-2]
 - Comandos: useradd, usermod, chown

### Notación octal de permisos

### Permisos especiales - Sticky Bit
 - Conceptos: sticky bit

### Control de atributos de ficheros en Linux - Chattr y Lsattr
 - Comandos: cp, chattr, lsattr
 - Archivos: /etc/passwd-

### Permisos especiales - SUID y SGID
 - Comandos: xargs, pkexec, find
 - Conceptos: suid, sgid
 - Vulnerabilidades: PwnKit

### Cuestionario de permisos

### Privilegios especiales - Capabilities
 - Comandos: getcap
 - Archivos: /etc/shells
 - Recursos: https://gtfobins.github.io/

### Estructura de directorios del sistema
 - Directorios:
   - sbin: binarios de root
   - bin: binarios de usuarios
   - usr: programas de usuario
   - boot: arranque del sistema
   - dev: particiones/almacenamiento
   - media: volumenes montados temporalmente
   - etc: archivos de configuracion (sistema + usuario)
   - home: archivos y configuraciones de los usuarios
   - root: archivos y configuraciones del root
   - lib: bibliotecas compartidas (.so) y modulos del kernel
   - lib64: lo mismo que lib pero para 64 bits
   - opt: extension de /usr archivos de solo lectura de programas autocontenidas (como el program files de windows)
   - proc: procesos que se estan ejecutando
   - sys: archivos virtuales relativos a eventos del sistema operativo (utiliza jerarquias)
   - srv: archivos relativos a servidores (web, ftp, etc)
   - tmp: archivos temporales, se limpia con cada reinicio
   - var: registro del sistema: logs, emails, bases de datos, cache, etc

### Uso de bashrc y zshrc
 - Comandos: hostname, awk, cut
 - Archivos: .bashrc
 - Conceptos: archivos ocultos (empiezan con .)

### Actualización y Upgradeo del sistema
 - Comandos: apt, parrot-upgrade, reboot

### Uso y manejo con Tmux
 - Comandos: who

### Búsquedas a nivel de sistema
 - Comandos: find, man
 - Recursos: https://www.youtube.com/watch?v=fshLf6u8B-w

### Creación de scripts en Bash
 - Comandos: ip, tr, tail, bash

### Uso y configuración de la Kitty

### Uso del editor Vim
 - Comandos: vim

### Conexiones SSH
 - Comandos: ssh, sshpass
 - Variables de entorno: $TERM
 - Recursos: https://overthewire.org/wargames/bandit/
 - util:
   - export TERM=xterm

### Lectura de archivos especiales [1-2]
 - Comandos: rev
 - Atajos: ctrl+k, ctrl+l

### Lectura de archivos especiales [2-2]
 - Comandos: file

### Directorios y archivos ocultos

### Detección del tipo y formato de archivos

### Búsquedas precisas de archivos [1-2]

### Búsquedas precisas de archivos [2-2]

### Métodos de filtrado de datos [1-2]
 - Comandos: sed

### Método de filtrado de datos [2-2]
 - Comandos: sort, uniq

### Interpretación de archivos binarios
 - Comandos: strings

### Codificación y decodificación en base64
 - Comandos: base64

### Cifrado césar y uso de tr para la traducción de caracteres

### Creamos un descompresor recursivo automático de archivos en Bash
 - Comandos: xxd, tee, sponge, gunzip, 7z
 - Flujos: !$
 - Bash: #!bin/bash, trap, sleep, exit, function, while

### Manejo de pares de claves y conexiones SSH
 - Comandos: systemctl, ssh-keygen, ssh-copy-id
 - Archivos: ~/.ssh/known_hosts, ~/.ssh/id_rsa, ~/.ssh/id_rsa.pub, ~/.ssh/autorized_keys

### Uso de netcat para realizar conexiones
 - Comandos: nc, netstat, ss, lsof
 - Archivos: /proc/net/tcp
 - Bash: for

### Uso de conexiones encriptadas
 - Comandos: ncat

### Creando nuestros propios escáneres en Bash
 - Comandos: timeout, nmap
 - Archivos: /dev/tcp/127.0.0.1/{puerto}
 - Bash: wait, tput civis, tput cnorm
 - Conceptos: id_rsa (permisos 600)

### Detección de diferencias entre archivos
 - Comandos: diff

### Ejecución de comandos por SSH

### Abusando de privilegio SUID para migrar de usuario

### Jugando con conexiones

### Abusando de tareas Cron [1-3]
 - Archivos: /etc/cron.d/

### Abusando de tareas Cron [2-3]
 - Cron: @reboot

### Abusando de tareas Cron [3-3]
 - Comandos: stat, mktemp, watch

### Comprendiendo las expresiones de las tareas Cron

### Cuestionario de tareas Cron

### Fuerza bruta aplicada a conexiones

### Escapando del contexto de un comando
 - Comandos: more

### Operando con proyectos de Github [1-5]
 - Comandos: git

### Operando con proyectos de Github [2-5]

### Operando con proyectos de Github [3-5]

### Operando con proyectos de Github [4-5]

### Operando con proyectos de Github [5-5]

### Argumentos posicionales en Bash

### Cuestionario de conceptos y comandos en Linux


Scripting en Bash - Principiante a Avanzado
===========================================

### PRIMER PROYECTO - Creando un buscador
 - Recursos: https://htbmachines.github.io/

### Scripting en Bash [1-6]
 - Comandos: curl
 - Bash: getops, case, declare, if, -eq, -ne, -gt, -lt, $OPTARG

### Scripting en Bash [2-6]
 - Comandos: md5sum
 - Bash: -f

### Scripting en Bash [3-6]

### Scripting en Bash [4-6]
 - Comandos: column

### Scripting en Bash [5-6]

### Scripting en Bash [6-6]

### SEGUNDO PROYECTO – Desafiando la ruleta de un casino

### Scripting en Bash [1-15]

### Scripting en Bash [2-15]

### Scripting en Bash [3-15]

### Scripting en Bash [4-15]
 - Comandos: read, bc
 - Variables de entorno: $RANDOM

### Scripting en Bash [5-15]

### Scripting en Bash [6-15]
 - Bash: let

### Scripting en Bash [7-15]

### Scripting en Bash [8-15]
 - Bash: declare -i, declare -a
 - Arrays: @ # -1 unset

### Scripting en Bash [9-15]

### Scripting en Bash [10-15]

### Scripting en Bash [11-15]

### Scripting en Bash [12-15]

### Scripting en Bash [13-15]

### Scripting en Bash [14-15]

### Scripting en Bash [15-15]


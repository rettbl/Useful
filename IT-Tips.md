# Useful

> Le but de ce document est de regrouper les différents informations à propos de l'IT dans un seul répository accessible de partout

## CTF

### Tools

- https://github.com/vavkamil/awesome-bugbounty-tools (regroupe les tools CTF)

### Tips

- ' or 1=1- - --> Bypass authentification web

## Linux

- Monter USB --> mount /dev/usbNAME /media/usb
  - Trouver sa clé USB --> sudo blkid
  
- Monter serveur python --> python3 -m http.server 555 --bind 192.168.1.1
   - Croc --> Envoyer des fichiers entre 2 PC

- #kali-undercover --> transforme le GUI en Windows

- last --> dernière connexion
- lastb --> dernière connexion qui à échoué

- find / -name XXX --> trouver un fichier dans le système

- lastlog --> Voir les différents comptes et leurs dernières connexions


## Malware

### Tools

- Virus Total --> étudier un fichier

- MRT --> Analyse PC

- HOIC --> Attaque DDOS

- https://gtfobins.github.io/ (liste de binaires vulnérables avec POC)

- https://github-wiki-see.page/m/hak5darren/USB-Rubber-Ducky/wiki/Payloads (liste payloads pour attaque via USB)


### Windows 

- ECHO@OFF start (mettre le fichier en .bat)

- %0|%0 (mettre le fichier en .bat) --> Ralentis l'ordinateur

## Forensics

- OsForensics --> Fouiller un PC

- BleachBit --> Supprime les fichiers de façon définitive

- TestDisk --> Recover Data

- MVT --> analyse de téléphone

- Medicat --> Fait sauter les mots de passe

- Kon Boot --> Supprime le mot de passe à la volée

## OSINT

- Script G-Hunt --> Rassemble les informations à partir d'une adresse mail google

- NexFil --> Trouve les réseaux sociaux d'une personne

## Photo

- Real Esrgan --> améliore la qualité des photos

- Resizer.in --> Augmente/Diminue une image en gardant la qualité

- Deface --> Flouter des visages

## Backup

- Pika Backup

- Auto Archiver

- Redo Rescue

- MeeroDrop --> Transfert de fichier jusqu'à 20 Go

- Blomp --> Cloud jusqu'a 200 Go

## Windows 
  
- dir C:\*.ova /S | more --> Recherche dans le système un fichier .ova

- Netstat -anpe --> Tout les flux actifs actutellement

- TronScript --> Evalue le PC et remonte les problèmes

- Powercfg /batteryreport --> Sort un rapport sur l'état de la batterie

- ipconfig /displaydns | find porn --> voir les recherches DNS

## Other

- Barrier --> permet d'avoir plusieurs PC sur 1 PC

- Locust --> Test de montée en charge

- DroidCam --> Transforme le téléphone en Webcam

- Automata --> Automatise des tâches Web

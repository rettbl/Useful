# RED TEAM

## Windows

1. Initial Foothold

- Sur quel OS nous sommes `powershell Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture`
- Nous sommes dans un domaine ou pas --> `powershell (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain`
  - Si oui lequel --> `powershell (Get-WmiObject -Class Win32_ComputerSystem).Domain`

- Lister les utilisateurs locaux --> `powershell Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet`
- Membres du groupes administrateurs local --> `powershell Get-LocalGroupMember -Group "Administrators"`
- Quel est l'adresse IP du DC ? --> `powershell Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site`


https://xbz0n.sh/blog/living-off-the-land-windows

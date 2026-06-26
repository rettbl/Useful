# RED TEAM

## Windows

1. Initial Foothold

- Sur quel OS nous sommes `Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture`
- Nous sommes dans un domaine ou pas --> `(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain`
  - Si oui lequel --> `(Get-WmiObject -Class Win32_ComputerSystem).Domain`

- Lister les utilisateurs locaux --> `Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet`
- Membres du groupes administrateurs local --> `Get-LocalGroupMember -Group "Administrators"`


https://xbz0n.sh/blog/living-off-the-land-windows

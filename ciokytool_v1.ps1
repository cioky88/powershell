$Welcome ="
 _    _      _                            _          _____ _       _          _____  _____ 
| |  | |    | |                          | |        /  __ (_)     | |        |  _  ||  _  |
| |  | | ___| | ___ ___  _ __ ___   ___  | |_ ___   | /  \/_  ___ | | ___   _ \ V /  \ V / 
| |/\| |/ _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \  | |   | |/ _ \| |/ / | | |/ _ \  / _ \ 
\  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) | | \__/\ | (_) |   <| |_| | |_| || |_| |
 \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/   \____/_|\___/|_|\_\\__, \_____/\_____/
                                                                         __/ |             
                                                                        |___/              
  ___ ______   _____           _   _____           _       _     _   _  __   _____         
 / _ \|  _  \ |_   _|         | | /  ___|         (_)     | |   | | | |/  | |  _  |        
/ /_\ \ | | |   | | ___   ___ | | \ `--.  ___ _ __ _ _ __ | |_  | | | |`| | | |/' |        
|  _  | | | |   | |/ _ \ / _ \| |  `--. \/ __| '__| | '_ \| __| | | | | | | |  /| |        
| | | | |/ /    | | (_) | (_) | | /\__/ / (__| |  | | |_) | |_  \ \_/ /_| |_\ |_/ /        
\_| |_/___/     \_/\___/ \___/|_| \____/ \___|_|  |_| .__/ \__|  \___/ \___(_)___/         
                                                    | |                                    
                                                    |_|                                     
"
$Author = "Author: https://www.linkedin.com/in/bogdan-ciocotisan-90b45367/"

do {
Write-Host "$Welcome" -ForegroundColor red
Write-Host "$Author" -ForegroundColor green
Write-Host "`n$line"
Write-Host "================ Menu ================"
  [int]$userMenuChoice = 0
  while ( $userMenuChoice -lt 1 -or $userMenuChoice -gt 4) {
    Write-Host "1. Network configuration"
    Write-Host "2. Hostname of Server"
    Write-Host "3. Domain"
    Write-Host "4. Computers olders than 90 Days"
    Write-Host "5. Export all AD groups and thier members"
    Write-Host "6. Create AD user"
    Write-Host "7. List inactive users from 30 days"
    Write-Host "8. List inactive computers from 30 days"
    Write-Host "9. List users of a specific AD Group"
    Write-Host "10. Export users of a specific AD Group"
    Write-Host "11. Add user to a specific AD Group"
    Write-Host "12. Add Bulk users creating from .csv"
    Write-Host "13. Delete AD user"
    Write-Host "14. Disable AD user"
    Write-Host "15. Enable AD user"
    Write-Host "16. Reset AD user password"
    Write-Host "17. Test AD user password"
    Write-Host "18. Rename AD Object, CN-Canonical Name"
    Write-Host "19. List all AD User proprietes"
    Write-Host "20. Check FSMO Roles"
    Write-Host "21. AD Replication status /showrepl"
    Write-Host "22. AD Replication status /replsummary"
    Write-Host "23. Display AD schema master"
    Write-Host "24. DHCP server export config .txt"
    Write-Host "25. DHCP server import config"
    Write-Host "26. NPS server export config .xml"
    Write-Host "27. NPS server import config"
    Write-Host "28. Windows Server Update"
    Write-Host "29. Enable Firewall PING ICMP IPv4 & IPv6"
    Write-Host "30. Disable firewall PING ICMP IPv4 & IPv6"
    Write-Host "31. AD Show last Backup of RepAdminTool"
    Write-Host "32. Backing Up AD, get Windows Backup"
    Write-Host "33. Backing Up AD, install Windows Backup Role"
    Write-Host "34. Backing Up AD locally"
    Write-Host "35. Map a network share folder"
    Write-Host "36. Backing Up AD to Network Path"
     
    Write-Host "Q. Quit and Exit"
    Write-Host "`n$line"

    [int]$userMenuChoice = Read-Host "Please choose an option"

    switch ($userMenuChoice) {
      1{ipconfig;
	  Write-Host "Success !!!" -ForegroundColor green
      Read-Host -Prompt “Press Enter to exit”}
      
      2{hostname; 
	  Write-Host "Success !!!" -ForegroundColor green
      Read-Host -Prompt “Press Enter to exit”}
      
      3{Get-ADDomain;
	  Write-Host "Success !!!" -ForegroundColor green
      Read-Host -Prompt “Press Enter to exit”}

      4{
        # Gets time stamps for all computers in the domain that have NOT logged in since after specified date 
        # Mod by Tilo 2013-08-27 
		$DateTime = Get-Date -f "yyyy-MM"
        import-module activedirectory  
        $domain = Get-ADDomainController -filter * | select domain
  
        $DaysInactive = 90  
        $time = (Get-Date).Adddays(-($DaysInactive)) 
  
        # Get all AD computers with lastLogonTimestamp less than our time 
        Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties LastLogonTimeStamp | 
  
        # Output hostname and lastLogonTimestamp into CSV 
        select-object Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}} | export-csv c:\OLD_Computer"+$DateTime+".csv -notypeinformation 
        Write-Host "Success !!!" -ForegroundColor green
		Write-Host "The list was exported on c:\OLD_Computer"+$DateTime+".csv"
		Read-Host -Prompt “Press Enter to exit”}
       
       5{
        #// Start of script 
        #// Get year and month for csv export file 
        $DateTime = Get-Date -f "yyyy-MM" 
 
        #// Set CSV file name 
        $CSVFile = "C:\AD_Groups"+$DateTime+".csv" 
 
        #// Create emy array for CSV data 
        $CSVOutput = @() 
 
        #// Get all AD groups in the domain 
        $ADGroups = Get-ADGroup -Filter * 
 
        #// Set progress bar variables 
        $i=0 
        $tot = $ADGroups.count 
 
        foreach ($ADGroup in $ADGroups) { 
        #// Set up progress bar 
        $i++ 
        $status = "{0:N0}" -f ($i / $tot * 100) 
        Write-Progress -Activity "Exporting AD Groups" -status "Processing Group $i of $tot : $status% Completed" -PercentComplete ($i / $tot * 100) 
 
        #// Ensure Members variable is empty 
        $Members = "" 
 
        #// Get group members which are also groups and add to string 
        $MembersArr = Get-ADGroup -filter {Name -eq $ADGroup.Name} | Get-ADGroupMember |  select Name 
        if ($MembersArr) { 
            foreach ($Member in $MembersArr) { 
                $Members = $Members + "," + $Member.Name 
            } 
            $Members = $Members.Substring(1,($Members.Length) -1) 
        } 
 
        #// Set up hash table and add values 
        $HashTab = $NULL 
        $HashTab = [ordered]@{ 
        "Name" = $ADGroup.Name 
        "Category" = $ADGroup.GroupCategory 
        "Scope" = $ADGroup.GroupScope 
        "Members" = $Members 
        } 
 
        #// Add hash table to CSV data array 
        $CSVOutput += New-Object PSObject -Property $HashTab 
        } 
 
        #// Export to CSV files 
        $CSVOutput | Sort-Object Name | Export-Csv $CSVFile -NoTypeInformation 
 
        #// End of script
		Write-Host "Success !!!" -ForegroundColor green
        Write-Host "The list was exported on C:\AD_Groups"+$DateTime+".csv"
		Read-Host -Prompt “Press Enter to exit”}

      6{$Name = Read-Host -Prompt 'Enter the name *'
        $SurName = Read-Host -Prompt 'Enter the Surname *'
        $SamAccountName = Read-Host -Prompt 'Enter the accountname *'
        $UserPrincipalName = Read-Host -Prompt 'Enter the full accountname with @domain *'
		$EMail = Read-Host -Prompt 'Enter the Email *'
        
        New-ADUser -Name $Name -GivenName $GivenName -Surname $Name -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -EMail $EMail -Path "OU=cioky_users,DC=cioky,DC=corp" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true
        
        <#Set variable to send email#>
        $From = "cioky88.cioky.corp"
        $To  = "ciocotisan.bogdan@gmail.com"
        $Subject = "cioky88 AD tool Script"
        $SMTPYahoo = "smtp.mail.yahoo.com"

        <#Send-MailMessage -From $From -To $To -Subject $Subject#>
	    Send-MailMessage -To $To -From $From -Subject $Subject -Body “Some important plain text!” -Credential (Get-Credential) -SmtpServer $SMTPYahoo -Port 587

        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

      7{dsquery user -inactive 30;
	    Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

      8{dsquery computer -inactive 30;
	    Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}
      
      9{$GroupName = Read-Host -Prompt 'Enter the Group name'
        Get-ADGroupMember -Identity $GroupName -Recursive | Select name
	    Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}
        
      10{$DateTime = Get-Date -f "yyyy-MM"
        $GroupNameExp = Read-Host -Prompt 'Enter the Group name'
        <#Get-ADGroupMember $GroupNameExp | Select Name, SamAccountName, EMail | Export-CSV C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv#>
        Get-adgroupmember $GroupNameExp | % {get-aduser $_ -properties emailaddress} | Select Name, SamAccountName, EMailaddress | Export-CSV C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv

        Write-Host "The list was exported on C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv"
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

       11{$GroupNameS = Read-Host -Prompt 'Enter the Group name'
         $UsernameS = Read-Host -Prompt 'Enter the user name'
        
	    Write-Host "User "$UsernameS" has been added to "$GroupNameS" group "
        Add-ADGroupMember -Identity $GroupNameS -Members $UsernameS
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        12{Add-Content -Path C:\Create_AD_Bulk_Users.csv  -Value '"firstname";"middleInitial";"lastname";"username";"email";"streetaddress";"city";"zipcode";"state";"country";"department";"password";"telephone";"jobtitle";"company";"ou"'
        Write-Host "The template was created on C:\Create_AD_Bulk_Users.csv " -ForegroundColor green
        Write-Host "`n$line"

        Write-Host "Populate the csv template with the data save it and" -ForegroundColor green
        Write-Host "return to script and press Enter to confirm and launch the creation" -ForegroundColor green
        Write-Host "!!! For csv creation use ; like separator" -ForegroundColor red
        Write-Host "And use Character Set: Unicode (UTF-8)" -ForegroundColor red
        Write-Host "* Mandatory columns to run: firstname, lastname, username, password, OU" -ForegroundColor red
        Write-Host "`n$line"

        Read-Host -Prompt “Preview ot template C:\Create_AD_Bulk_Users.csv”
        Import-Csv C:\Create_AD_Bulk_Users.csv -Delimiter ";" | Format-Table
        Read-Host -Prompt “Press Enter to Confirm the Bulk creation”
        
        # Import active directory module for running AD cmdlets
        Import-Module ActiveDirectory
  
        # Store the data from NewUsersFinal.csv in the $ADUsers variable
        $ADUsers = Import-Csv C:\Create_AD_Bulk_Users.csv -Delimiter ";"

        # Define UPN
        $UPN = "cioky.corp"

        # Loop through each row containing user details in the CSV file
        foreach ($User in $ADUsers) {

        #Read user data from each field in each row and assign the data to a variable as below
        $username = $User.username
        $password = $User.password
        $firstname = $User.firstname
        $lastname = $User.lastname
        $initials = $User.initials
        $OU = $User.ou #This field refers to the OU the user account is to be created in
        $email = $User.email
        $streetaddress = $User.streetaddress
        $city = $User.city
        $zipcode = $User.zipcode
        $state = $User.state
        $telephone = $User.telephone
        $jobtitle = $User.jobtitle
        $company = $User.company
        $department = $User.department

        # Check to see if the user already exists in AD
        if (Get-ADUser -F { SamAccountName -eq $username }) {
        
        # If user does exist, give a warning
        Write-Warning "A user account with username $username already exists in Active Directory."
        }
        else {

        # User does not exist then proceed to create the new user account
        # Account will be created in the OU provided by the $OU variable read from the CSV file
        New-ADUser `
            -SamAccountName $username `
            -UserPrincipalName "$username@$UPN" `
            -Name "$firstname $lastname" `
            -GivenName $firstname `
            -Surname $lastname `
            -Initials $initials `
            -Enabled $True `
            -DisplayName "$lastname, $firstname" `
            -Path $OU `
            -City $city `
            -PostalCode $zipcode `
            -Company $company `
            -State $state `
            -StreetAddress $streetaddress `
            -OfficePhone $telephone `
            -EmailAddress $email `
            -Title $jobtitle `
            -Department $department `
            -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $True

        # If user is created, show message.
        Write-Host "The user account $username is created." -ForegroundColor Cyan
            }
        }

        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        13{$DellName = Read-Host -Prompt 'Enter the name of the user'
        
        Remove-ADUser -Identity $DellName
        
        Write-Host "The user $DellName has been deleted with success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        14{$DisableName = Read-Host -Prompt 'Enter the name of the user'

        Disable-ADAccount -Identity $DisableName

        Write-Host "The user $DisableName has been disabled with success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        15{$EnableName = Read-Host -Prompt 'Enter the name of the user'

        Enable-ADAccount -Identity $EnableName

        Write-Host "The user $EnableName has been enabled with success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        16{$ResetPasswd = Read-Host -Prompt 'Enter the name of the user'
           $NewPasswd = Read-Host -Prompt 'Enter the password for the user'

        Set-ADAccountPassword -Identity $ResetPasswd -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $NewPasswd -Force)


        Write-Host "The password of user $ResetPasswd has been reseted with success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        17{$TestUsr = Read-Host -Prompt 'Enter the username'
           $TestPasswd = Read-Host -Prompt 'Enter the password'

        Function Test-ADAuthentication {
        param($username,$password)
        (new-object directoryservices.directoryentry "",$TestUsr,$TestPasswd).psbase.name -ne $null 
        }
        <#Test-ADAuthentication "test" "Password1"#>
        Read-Host -Prompt “Press Enter to exit”}

        18{$CNUsr = Read-Host -Prompt 'Enter the username'
        <#Get-ADUser -Identity $CNUsr -Properties *#>

        <#Rename-ADObject -Identity "OU=ManagedGroups,OU=Managed,DC=Fabrikam,DC=Com" -NewName "Groups"#>
        
        <#Read-Host -Prompt “Press Enter to exit”}#>}

        19{$CNUsrProp = Read-Host -Prompt 'Enter the username'
        Get-ADUser -Identity $CNUsrProp -Properties *
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        20{netdom query fsmo
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        21{repadmin /showrepl
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        22{repadmin /replsummary
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        23{netdom query fsmo
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        24{$DateTime = Get-Date -f "yyyy-MM"
        netsh dhcp server export c:\DHCP_config_$DateTime.txt all
        Write-Host "The DHCP config c:\DHCP_config_$DateTime.txt was exported" -ForegroundColor green
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        25{$DHCPfilePath = Read-Host -Prompt 'Enter the path of DHCP config with extension .txt'
        netsh dhcp server import $DHCPfilePath
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        26{$DateTime = Get-Date -f "yyyy-MM"
        export-npsconfiguration -Path c:\NPS_conflig_$DateTime.xml
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        27{$NPSfilePath = Read-Host -Prompt 'Enter the path of DHCP config with extension .xml'
        Import-NpsConfiguration -Path $NPSfilePath
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}
         
        28{Write-Host "1. Download the file pswindowsupdate.2.2.0.2.nupkg from:"
        Write-Host "https://www.powershellgallery.com/packages/PSWindowsUpdate/2.2.0.2"
        Write-Host "2. Go to %WINDIR%\System32\WindowsPowerShell\v1.0\Modules create e new folder PSWindowsUpdate"
        Write-Host "3. Copy pswindowsupdate.2.2.0.2.nupkg in PSWindowsUpdate Folder"
        Write-Host "4. Open a PowerShell with run as admin and run Set-ExecutionPolicy RemoteSigned"
        Read-Host -Prompt “Press Enter after you copy the module pswindowsupdate.2.2.0.2.nupkg”
        
        <#Set-ExecutionPolicy RemoteSigned#>

        Import-Module -Name PSWindowsUpdate

        Install-Module -Name PSWindowsUpdate

        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        29{#IPv4
        netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

        #IPv6
        netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol="icmpv6:8,any" dir=in action=allow
        
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        30{#IPv4
        netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=block

        #IPv6
        netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol="icmpv6:8,any" dir=in action=block
        
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        31{repadmin /showbackup
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        32{Get-WindowsFeature Windows-Server-Backup
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        33{Add-Windowsfeature Windows-Server-Backup –Includeallsubfeature
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        34{Write-Host "Function not available !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        35{$DriveLeter = Read-Host -Prompt “Press a drive leter for network share folder ex: E:,M:,X:”
            $ShServer = Read-Host -Prompt “Enter a server and share name: \\server\share”
            $ShUser = Read-Host -Prompt “Enter the user of share server”
            $ShPasswd = Read-Host -Prompt “Enter the password of share server”
            $net = new-object -ComObject WScript.Network
           $net.MapNetworkDrive($DriveLeter, $ShServer, $false, $ShUser, $ShPasswd)

           Write-Host "Success !!!" -ForegroundColor green
           Read-Host -Prompt “Press Enter to exit”}

        36{Import-Module ServerManager
        [string]$date = get-date -f 'yyyy-MM-dd'
        Write-Host "Network path example:" -ForegroundColor red
        Write-Host "\\server\share (shared folder)" -ForegroundColor green
        Write-Host "http://webserver/share (Web Share)" -ForegroundColor green
        Write-Host "ftp://ftp.microsoft.com (FTP site)" -ForegroundColor green

        $path=Read-Host -Prompt 'Enter the Network path to save Windows AD Backup'
        $TargetUNC=$path+$date
        $TestTargetUNC= Test-Path -Path $TargetUNC
        if (!($TestTargetUNC)){
        New-Item -Path $TargetUNC -ItemType directory
        }
        $WBadmin_cmd = "wbadmin.exe START BACKUP -backupTarget:$TargetUNC -systemState -noverify -vssCopy -quiet"
        Invoke-Expression $WBadmin_cmd
        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        default {
		Write-Host "Error !!!" -ForegroundColor red
		Write-Host "Select a valid option !!!" -ForegroundColor red} 
    }
  }
} while ( $userMenuChoice -ne 99 )
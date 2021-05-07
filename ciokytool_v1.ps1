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

$path = "C:\ADtool\"
If(!(test-path $path))
{
      Write-Host "The folder $path was created !!!" -ForegroundColor green
      New-Item -ItemType Directory -Force -Path $path | Out-Null
}

do {
Write-Host "$Welcome" -ForegroundColor red
Write-Host "$Author" -ForegroundColor green
Write-Host "`n$line"
Write-Host "================ Menu ================"
  [int]$userMenuChoice = 0
  while ( $userMenuChoice -lt 1 -or $userMenuChoice -gt 4) {
    Write-Host "1. IP network configuration"
    Write-Host "2. Server' hostname"
    Write-Host "3. Display the Domain Name"
    Write-Host "4. Computers with old AD communication"
    Write-Host "5. Export all AD groups and thier members"
    Write-Host "6. Create AD user in a specific OU"
    Write-Host "7. List inactive users from 30 days"
    Write-Host "8. List inactive computers from 30 days"
    Write-Host "9. List users from a specific AD Group"
    Write-Host "10. Export users from a specific AD Group"
    Write-Host "11. Add user to a specific AD Group"
    Write-Host "12. Import Bulk users in AD from .csv file"
    Write-Host "13. Delete AD user"
    Write-Host "14. Disable AD user"
    Write-Host "15. Enable AD user"
    Write-Host "16. Reset AD user password"
    Write-Host "17. Test AD user password"
    Write-Host "18. Rename AD User CN Object, (CN=Canonical Name)"
    Write-Host "19. List all proprietes of a AD User "
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
    Write-Host "37. Copy All users from an group to another"
    Write-Host "38. Lista all users from an OU"
    Write-Host "39. Move all users from an OU to another"
    Write-Host "40. Check for  stations with Broken Trust Relationship"
    Write-Host "41. Create AD user in default Users OU"
    Write-Host "42. Export users from many groups to one *.CSV"
     
    Write-Host "Q. Quit and Exit"
    Write-Host "`n$line"

    [int]$userMenuChoice = Read-Host "Please choose an option"
    Write-Host "`n$line"

    switch ($userMenuChoice) {

      1{ipconfig;
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}
      
      2{hostname; 
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}
      
      3{Get-ADDomain;
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}

      4{$DateTime = Get-Date -f "yyyy-MM"
        import-module activedirectory 
        $path4 = "C:\ADtool\Old_Computers\"
            If(!(test-path $path4))
                {
                    New-Item -ItemType Directory -Force -Path $path4 | Out-Null
                } 
        $domain = Get-ADDomainController -filter * | select domain
        $DaysInactive = Read-Host -Prompt 'Enter the number of days passed since the last communication' 
        $time = (Get-Date).Adddays(-($DaysInactive)) 
  
        # Get all AD computers with lastLogonTimestamp less than our time 
        Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties LastLogonTimeStamp | 
  
        # Output hostname and lastLogonTimestamp into CSV 
        select-object Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}} | export-csv C:\ADtool\Old_Computers\Old_Computers"+$DateTime+".csv -notypeinformation 
            Write-Host "`n$line"
            Write-Host "Success !!!" -ForegroundColor green
		    Write-Host "The list was exported on " –NoNewline
            Write-Host "C:\ADtool\Old_Computer\Old_Computers"+$DateTime+".csv" -ForegroundColor red
            Write-Host "`n$line"
		Read-Host -Prompt “Press Enter to return to main menu”}
       
     5{$DateTime = Get-Date -f "yyyy-MM" 
       $path5 = "C:\ADtool\AD_groups_members\"
            If(!(test-path $path5))
                {
                    New-Item -ItemType Directory -Force -Path $path5 | Out-Null
                } 
       $CSVFile = "C:\ADtool\AD_groups_members\All_AD_groups_and_members"+$DateTime+".csv" 
 
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
            Write-Host "`n$line"
		    Write-Host "Success !!!" -ForegroundColor green
            Write-Host "The list was exported on C:\ADtool\AD_groups_members\All_AD_groups_and_members"+$DateTime+".csv"
            Write-Host "`n$line"
		Read-Host -Prompt “Press Enter to return to main menu”}

      6{Write-Host "This method required the path of the OU"
        Write-Host "OU structure example: OU=Cluj,OU=Romania,OU=cioky_users"-ForegroundColor green
        Write-Host "- cioky_users" -ForegroundColor red
        Write-Host " - Romania" -ForegroundColor red
        Write-Host "  - Cluj" -ForegroundColor red
        Write-Host "`n$line"

        $UserOU = Read-Host -Prompt 'Enter the OU path *'
        $Name = Read-Host -Prompt 'Enter the name *'
        $SurName = Read-Host -Prompt 'Enter the Surname *'
        $SamAccountName = Read-Host -Prompt 'Enter the accountname *'
        $Domain = (Get-ADDomain).DNSRoot
        $UserPrincipalName = "$SamAccountName@$Domain"
		$EMail = Read-Host -Prompt 'Enter the Email *'
        $string = (Get-ADDomain).UsersContainer
        #$string = "CN=Users,DC=cioky,DC=corp"
        $a, $b, $c = $string.split(",")
        
        New-ADUser -Name $Name -GivenName $GivenName -Surname $Name -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -EMail $EMail -Path "$UserOU,$b,$c" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true
        
        <#Set variable to send email
        $From = "cioky88.cioky.corp"
        $To  = "ciocotisan.bogdan@gmail.com"
        $Subject = "cioky88 AD tool Script"
        $SMTPYahoo = "smtp.mail.yahoo.com"#>

        <#Send-MailMessage -From $From -To $To -Subject $Subject#>
	    <#Send-MailMessage -To $To -From $From -Subject $Subject -Body “Some important plain text!” -Credential (Get-Credential) -SmtpServer $SMTPYahoo -Port 587
#>          
            
            Write-Host "`n$line"
            Write-Host "Success !!!" -ForegroundColor green
            Write-Host "The user "–NoNewline
            Write-Host "$SamAccountName " –NoNewline -ForegroundColor red
            Write-Host "was created on $UserOU!"
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}

      7{dsquery user -inactive 30;
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}

      8{dsquery computer -inactive 30;
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}
      
      9{$GroupName = Read-Host -Prompt 'Enter the Group name'
        Get-ADGroupMember -Identity $GroupName -Recursive | Select name
            Write-Host "`n$line"
	        Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}
        
      10{$DateTime = Get-Date -f "yyyy-MM"
        $GroupNameExp = Read-Host -Prompt 'Enter the Group name'
        <#Get-ADGroupMember $GroupNameExp | Select Name, SamAccountName, EMail | Export-CSV C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv#>
        Get-adgroupmember $GroupNameExp | % {get-aduser $_ -properties emailaddress} | Select Name, SamAccountName, EMailaddress | Export-CSV C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv

            Write-Host "The list was exported on C:\AD_"$GroupNameExp"_Group_Members_"$DateTime".csv"
            Write-Host "`n$line"
            Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}

       11{$GroupNameS = Read-Host -Prompt 'Enter the Group name'
         $UsernameS = Read-Host -Prompt 'Enter the user name'
        
	        Write-Host "User "$UsernameS" has been added to "$GroupNameS" group "
        Add-ADGroupMember -Identity $GroupNameS -Members $UsernameS
            Write-Host "`n$line"
            Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to return to main menu”}

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

        18{$CNUsr = Read-Host -Prompt 'Enter the username: '
        Write-Host "`n$line"
        #get-aduser -filter * -properties * | ?{$_.Enabled -eq $True} | Select SamAccountName,UserPrincipalName,givenName,surName,Title,Department,CanonicalName,employeeID | Export-Csv c:\whateverdirectory\userlist.csv

          $UserCN = get-aduser -filter {SamAccountName -like $CNUsr} -properties * | ?{$_.Enabled -eq $True} | Select CanonicalName
          #$UsrGUID = get-aduser -filter {SamAccountName -like $CNUsr} -properties * | ?{$_.Enabled -eq $True} | Select ObjectGUID
          $UsrGUID = (get-aduser -identity $CNUsr).ObjectGUID 
          $UsrCannNamd = (get-aduser -identity $CNUsr).CanonicalName
          
          Write-Host "The CanonicalName of the user is "
          Write-Host $UserCN
          Write-Host "`n$line"
          $RenameObj = Read-Host -Prompt 'Enter the New Canonical Name of the user Object'
          Write-Host "`n$line"
          Rename-ADObject -Identity $UsrGUID -NewName $RenameObj

          Write-Host "The New CanonicalName of the user Object is: "
          $UserCNNew = get-aduser -filter {SamAccountName -like $CNUsr} -properties * | ?{$_.Enabled -eq $True} | Select CanonicalName
          Write-Host $UserCNNew
            Write-Host "`n$line"
            Write-Host "Success !!!" -ForegroundColor green
            Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to exit”}

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

        37{$SGroup = Read-Host -Prompt “Enter the name of the source Group”
            $DGroup = Read-Host -Prompt “Enter the name of the destination Group”
            Get-ADGroupMember -Identity $SGroup | ForEach-Object {Add-ADGroupMember -Identity $DGroup -Members $_.distinguishedName}

        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        38{$DC1 = Read-Host -Prompt “Enter the domain extension, com,corp, etc”
            $DC2 = Read-Host -Prompt “Enter the domain name”
            $OU = Read-Host -Prompt “Enter the name of the OU"
            Get-Aduser -Filter * -Searchbase "ou=$OU,dc=$DC2,dc=$DC1" | Select SamAccountName

        Write-Host "Success !!!" -ForegroundColor green
        Read-Host -Prompt “Press Enter to exit”}

        39{$string = (Get-ADDomain).UsersContainer
        #$string = "CN=Users,DC=cioky,DC=corp"
        $a, $b, $c = $string.split(",")
        $OldOU = Read-Host -Prompt “Enter the name of the current OU”
        $NewOU = Read-Host -Prompt “Enter the name of the new OU”

        Rename-ADObject -Identity "OU=$OldOU,$b,$c" -NewName $NewOU
        Write-Host "`n$line"
        Write-Host "All users from $OldOU was moved in $NewOU"
        Write-Host "`n$line"
        Write-Host "Success !!!" -ForegroundColor green
        Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to exit”}

        40{


        Write-Host "`n$line"
        Write-Host "Success !!!" -ForegroundColor green
        Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to exit”}

        41{


        Write-Host "`n$line"
        Write-Host "Success !!!" -ForegroundColor green
        Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to exit”}

        42{
        
<#$groupNames = 'HR','Engineering','Finance'
$users_list = @()

foreach ($group in $groupNames) 
    {
   
     $user = Get-ADGroupmember -identity $group | select name 
     $users_list += $user

    }

$users_list | sort name -Unique | Export-Csv 'c:\MultiGuroups.csv' -NoClobber -NoTypeInformation

#Write-Host $users_list
<#$FileName2 = "c:\MultiGuroups_Sorted.csv"
if (Test-Path $FileName2) 
{
  Remove-Item $FileName2
}

Import-Csv c:\MultiGuroups.csv | sort name -Unique | Export-Csv 'c:\MultiGuroups_Sorted.csv' -NoClobber -NoTypeInformation -Append

$FileName = "c:\MultiGuroups.csv"
if (Test-Path $FileName) 
{
  Remove-Item $FileName
} #>

        $FileName = "c:\MultiGuroups.csv"
        if (Test-Path $FileName) 
            {
                Remove-Item $FileName
            }

        $groupNames = Read-Host -Prompt “Enter the group name separated by coma ex: HR, IT ”

        foreach ($group in $groupNames) 
            {
   
                Get-ADGroupmember -identity $group | select name  | Export-Csv -path c:\MultiGuroups.csv -Append
    
            }

        $FileName2 = "c:\MultiGuroups_Sorted.csv"
        if (Test-Path $FileName2) 
            {
                Remove-Item $FileName2
            }

        Import-Csv c:\MultiGuroups.csv | sort name -Unique | Export-Csv 'c:\MultiGuroups_Sorted.csv' -NoClobber -NoTypeInformation -Append

        $FileName = "c:\MultiGuroups.csv"
        if (Test-Path $FileName) 
            {
                Remove-Item $FileName
            }
        Write-Host "`n$line"
        Write-Host "Success !!!" -ForegroundColor green
        Write-Host "`n$line"
        Read-Host -Prompt “Press Enter to exit”}
        
        

        default {
		Write-Host "Error !!!" -ForegroundColor red
		Write-Host "Select a valid option !!!" -ForegroundColor red
        Write-Host "`n$line"}
    }
  }
} while ( $userMenuChoice -ne 99 )
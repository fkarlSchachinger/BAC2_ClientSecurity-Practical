# BAC2_ClientSecurity-Practical

1. Download / wget the zipped files from this GitHub Repository
2. Extract the Files on your Domain Controller 
3. Create 1 Organizational Unit "CMPEmployees" for the Computer Policies 
4. Create 1 Organuzational Unit "UsersEmployees" for the User Policies
5. Open Powershell and Import the Module 

. .\SecuritySkript.ps1

4. Run the Script with following commandlet: 

InitiateMitigations

5. GPOs will be linked to the associatet OU's 
6. To enable Bitlocker and update the GPO at the End of the Skript you have to put in the Clientname of a client and access it as an administrator

Done

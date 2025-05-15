
# SYNOPSIS
# Create bulk Windows MACOS PKG Application in Intune Using PowerShell.

# DESCRIPTION
# This script automates the creation of MACOS PKG Applications in Intune using PowerShell.

# DEMO
# YouTube video link → https://www.youtube.com/@chandermanipandey8763

# INPUTS
# Provide all required information in the User Input section.

# OUTPUTS
# Automatically creates MACOS PKG Application in Intune using PowerShell.

# Note:-
# The file size must be 9MB or larger.
# 7-Zip application must be installed.You can download for:-  https://7-zip.org/download.html
# Info.plist or PackageInfo must be in the English language.


# NOTES
# Version:         V1.0  
# Author:          Chander Mani Pandey 
# Creation Date:   13 May 2025

# Find the author on:  
# YouTube:    https://www.youtube.com/@chandermanipandey8763  
# Twitter:    https://twitter.com/Mani_CMPandey  
# LinkedIn:   https://www.linkedin.com/in/chandermanipandey  
# BlueSky:    https://bsky.app/profile/chandermanipandey.bsky.social
# GitHub:     https://github.com/ChanderManiPandey2022

Clear-Host
Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' 
$error.clear() ## this is to clear error history 
$ErrorActionPreference = 'SilentlyContinue';

$AppName = $null;$Publisher =$null;$AppDownloadUrl = $null;$ApplogoDownloadUrl = $null
#=======================================================================#
#===============User Input Section Start================================#
#=======================================================================#
 
$7zPath = "C:\Program Files\7-Zip\7z.exe"                          # Ensure this path is correct; update if necessary
$GroupID = "5978daf2-f69b-46d9-b300-becc194337dd"                   # Entra Group Object ID 
$InstallMode = "Available"                                          # Options: Available, Required, Uninstall


#App 1
#$AppName = "Google Chrome"                                                                     # Application Name
#$Publisher = "Google Chrome"                                                                   # Application Publisher Name
#$AppDownloadUrl ="https://dl.google.com/dl/chrome/mac/universal/stable/gcem/GoogleChrome.pkg"  # Application PKG file download Location
#$ApplogoDownloadUrl = "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e1/Google_Chrome_icon_%28February_2022%29.svg/180px-Google_Chrome_icon_%28February_2022%29.svg.png"
#$appHomepage = 'https://www.google.com/chrome/'

#App 2
#$AppName = "Nextcloud"                                                                                                 # Application Name
#$Publisher = "Nextcloud"                                                                                               # Application Publisher Name
#$AppDownloadUrl ="https://download.nextcloud.com/desktop/releases/Mac/Installer/Nextcloud-3.16.4.pkg"                  # Application PKG file download Location
#$ApplogoDownloadUrl = "https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/Nextcloud_Logo.svg/240px-Nextcloud_Logo.svg.png"                        # Application Logo
#$appHomepage = 'https://nextcloud.com/'

#App 3
#$AppName = "1password"                                                                         # Application Name
#$Publisher = "1password"                                                                       # Application Publisher Name
#$AppDownloadUrl ="https://downloads.1password.com/mac/1Password.pkg"                           # Application PKG file download Location
#$ApplogoDownloadUrl = "https://upload.wikimedia.org/wikipedia/commons/5/5b/1Password_icon.png"             # Application Logo
#$appHomepage = 'https://1password.com/'

#App 4
$AppName = "Zoom"                                                                              # Application Name
$Publisher = "Zoom"                                                                            # Application Publisher Name
$AppDownloadUrl ="https://zoom.us/client/latest/Zoom.pkg"                                      # Application PKG file download Location
$ApplogoDownloadUrl = "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Zoom_Logo_2022.svg/500px-Zoom_Logo_2022.svg.png" # Application Logo
$appHomepage = 'https://www.zoom.com/'

#App 5
#$AppName = "Microsoft Teams"
#$Publisher = "Microsoft"
#$AppDownloadUrl ="https://go.microsoft.com/fwlink/p/?linkid=869428"
#$ApplogoDownloadUrl = "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c9/Microsoft_Office_Teams_%282018%E2%80%93present%29.svg/330px-Microsoft_Office_Teams_%282018%E2%80%93present%29.svg.png"
#$appHomepage = 'https://www.microsoft.com/en-us/microsoft-teams/group-chat-software'

#=============================================================#
#===============User Input Section END========================#
#=============================================================#


Write-Host ""
Write-Host "===============Creating and Publishing '$AppName  ====================" -ForegroundColor Green
Write-Host ""

# Function to check, install, and import a module
function Ensure-Module {
    param (
        [string]$moduleToCheck
    )
    $moduleStatus = Get-Module -Name $moduleToCheck -ListAvailable
    Write-Host "Checking if $moduleToCheck is installed" -ForegroundColor Yellow
    if ($moduleStatus -eq $null) {
        Write-Host "$moduleToCheck is not installed" -ForegroundColor Red
        Write-Host "Installing $moduleToCheck" -ForegroundColor Yellow
        Install-Module $moduleToCheck -Force
        Write-Host "$moduleToCheck has been installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "$moduleToCheck is already installed" -ForegroundColor Green
    }
    Write-Host "Importing $moduleToCheck module" -ForegroundColor Yellow
    Import-Module $moduleToCheck -Force
    Write-Host "$moduleToCheck module imported successfully" -ForegroundColor Green
}
Write-Host ""
# Ensure Microsoft.Graph.DeviceManagement.Enrollment is installed and imported
Ensure-Module -moduleToCheck "Microsoft.Graph.Authentication"

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -NoWelcome -ErrorAction Stop

# Define required directories
$MAC_PKG = "C:\Temp\MAC_PKG_App_Creator"
$App = "$MAC_PKG\$AppName"
$Source = "$App\Source"
$Output = "$App\Output"
$Logo = "$App\Logo"
$azCopyDirectory = "$MAC_PKG\AzCopy"

# Ensuring removal of previous execution leftovers
Remove-Item -Path $MAC_PKG -Recurse -Force

# Creating required directories
foreach ($dir in @($App, $Source, $Output, $Logo,$azCopyDirectory)) {
    if (!(Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host ""
#Download the application only if it doesn't already exist
if (!(Test-Path -Path $Source\*)) {
#$FinalUrl = 0
# Get the redirected URL 
$Response = Invoke-WebRequest -Uri $AppDownloadUrl -UseBasicParsing
$FinalUrl = $Response.BaseResponse.ResponseUri.AbsoluteUri
#$FileName = $null
# Extract the filename from the URL
$FileName = [System.IO.Path]::GetFileName($FinalUrl)

# Define full file path
$FilePath = Join-Path -Path $Source  -ChildPath $FileName

# Download the file
Invoke-WebRequest -Uri $FinalUrl -OutFile $FilePath

# Store the filename in a variable
$DownloadedFileName = [System.IO.Path]::GetFileName($FilePath)

# Output the filename
Write-host "Downloaded $DownloadedFileName application setup file" -ForegroundColor Green

} 
else 
{
    Write-Host "Application already exists at "$Source\$DownloadedFileName". Skipping download."
}

#Download the logo if not already downloaded
$LogoFile = "$Logo\logo.png"
if (!(Test-Path -Path $LogoFile)) {
    Write-Host "Downloaded $DownloadedFileName application logo" -ForegroundColor Green
    Invoke-WebRequest -Uri $ApplogoDownloadUrl -OutFile $LogoFile
} else {
    Write-Host "Logo already exists. Skipping download."
}
Write-Host ""




#===============================================================================================================================================================================================#
# Download and save AzCopy content.
$toolsFolderPath = $MAC_PKG
$azCopyDirectory = "$toolsFolderPath\AzCopy"
$azCopyDownloadUrl = "https://aka.ms/downloadazcopy-v10-windows"
$azCopyArchive = "$toolsFolderPath\azcopy.zip"

# Ensure PowerShell is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator" -ForegroundColor Red
    exit
}

# Create folder if it doesn't exist
if (!(Test-Path $toolsFolderPath)) {
    New-Item -Path $toolsFolderPath -ItemType Directory -Force | Out-Null
}

# Remove existing AzCopy folder
if (Test-Path $azCopyDirectory) {
    Remove-Item -Recurse -Force $azCopyDirectory
}

# Download and extract AzCopy
Invoke-WebRequest -Uri $azCopyDownloadUrl -OutFile $azCopyArchive
Expand-Archive -LiteralPath $azCopyArchive -DestinationPath $toolsFolderPath -Force
Remove-Item $azCopyArchive

# Find the extracted folder containing azcopy.exe
$azCopyExtractedFolder = Get-ChildItem -Path $toolsFolderPath -Directory | Where-Object { $_.Name -match "azcopy" }
if ($azCopyExtractedFolder) {
    Rename-Item "$toolsFolderPath\$azCopyExtractedFolder" $azCopyDirectory -Force
} else {
    Write-Host "AzCopy extraction failed. Check the downloaded zip contents." -ForegroundColor Red
    exit
}

# Verify if azcopy.exe exists
if (!(Test-Path "$azCopyDirectory\azcopy.exe")) {
    Write-Host "AzCopy executable not found!" -ForegroundColor Red
    exit
}

# Add AzCopy to system PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$azCopyDirectory", [System.EnvironmentVariableTarget]::Machine)

Write-Host "AzCopy installation completed successfully." -ForegroundColor Green

#===============================================================================================================================================================================================#
# Extract content using 7-Zip
# Ensure variables are properly defined
if (-not ($Source -and $DownloadedFileName -and $Output)) {
    Write-Host "Error: One or more required variables are not set."
    exit
}

# Run 7-Zip extraction

$Arguments = "x `"$Source\$DownloadedFileName`" -o`"$Output`" -y"
Start-Process -FilePath $7zPath -ArgumentList $Arguments -NoNewWindow -Wait | Out-Null
Write-Host "Extraction completed. Files are in: $Output" -ForegroundColor Green

# Find the Info.plist file recursively
$PackageInfo = Get-ChildItem -Path $Output -Recurse -Filter "PackageInfo" | Select-Object -ExpandProperty FullName -First 1

# Check if Info.plist was found
if ($PackageInfo) {
    Write-Host "PackageInfo found at: $PackageInfo" -ForegroundColor Green
    $pkginfo = "Found"
} else {
   # Write-Host "PackageInfo not found in $Output" -ForegroundColor Red
    $pkginfo = "NotFound"
    #return
}

if ($pkginfo -eq "Found")
{
# Path to the Info.plist file
Write-Host "$AppName PackageInfo file location is:- $PackageInfo " -ForegroundColor Yellow

# Read the first line of the file
$firstLine = Get-Content $PackageInfo -Encoding UTF8 | Select-Object -First 1

# Check if the first line contains the expected XML declaration
if ($firstLine -match '<\?xml version="1.0" encoding="UTF-8"\?>') 

{
    Write-Host "$AppName PackageInfo contains the expected XML declaration. Assuming English. Continuing..." -ForegroundColor Green
    
}
else{
# Checking if the info.plist file contains non-ASCII characters
if (Get-Content $PackageInfo -Encoding UTF8 | Select-String "[^\x00-\x7F]") {
    Write-Host "The $AppName PackageInfo contains non-ASCII (non-English) characters. Manually create application in Intune... Exiting." -ForegroundColor Red
    return
} else {
    Write-Host "The $AppName PackageInfo contains only ASCII (English) characters. Continuing..." -ForegroundColor Green
}
}
# Check if PackageInfo exists
if (Test-Path $PackageInfo) {
    # Load the XML content of PackageInfo
    [xml]$xmlContent = Get-Content -Path $PackageInfo
#=======================
# Get the first <bundle> element (adjust if you expect multiple)
$bundleNode = $xmlContent.SelectSingleNode("//bundle")
$bundleNode1 = $xmlContent.SelectSingleNode("//pkg-info")

$appVersion = $null
$bundleID = $null

if ($bundleNode -ne $null) {
    $appVersion = $bundleNode.CFBundleShortVersionString
    $bundleID = $bundleNode.id

    Write-Host "App Version: $appVersion"
    Write-Host "Bundle ID: $bundleID"
}
elseif ($bundleNode1 -ne $null) {
    $appVersion = $bundleNode1.version
    $bundleID = $bundleNode1.identifier

    Write-Host "App Version (from pkg-info): $appVersion"
    Write-Host "Bundle ID (from pkg-info): $bundleID"
}
else {
    Write-Host "No <bundle> or <pkg-info> node found." -ForegroundColor Red
    return
}
}
}

#=========================================

else
{
Write-Host "PackageInfo file not found.Checking Payload~ file pressent at the specified path." -ForegroundColor yellow

$Arguments = "x `"$output\Payload~`" -o`"$Output`" -y"
Start-Process -FilePath $7zPath -ArgumentList $Arguments -NoNewWindow -Wait | Out-Null
Write-Host "Extraction completed. Files are in: $Output" -ForegroundColor Green

# Find the Info.plist file recursively
#$PackageInfo = Get-ChildItem -Path $Output -Recurse -Filter "PackageInfo" | Select-Object -ExpandProperty FullName -First 1
$plistPath = Get-ChildItem -Path $Output -Recurse -Filter "Info.plist" | Select-Object -ExpandProperty FullName -First 1
# Check if Info.plist was found
if ($plistPath) {
    Write-Host "Info.plist found at: $plistPath" -ForegroundColor Green
} else {
    Write-Host "Info.plist not found in $Output" -ForegroundColor Red
    return
}

# Path to the Info.plist file
Write-Host "$AppName info.plist file location is:- $plistPath " -ForegroundColor Yellow

# Read the first line of the file
$firstLine = Get-Content $plistPath -Encoding UTF8 | Select-Object -First 1

# Check if the first line contains the expected XML declaration
if ($firstLine -match '<\?xml version="1.0" encoding="UTF-8"\?>') 

{
Write-Host "$AppName info.plist contains the expected XML declaration. Assuming English. Continuing..." -ForegroundColor Green
}
else{
# Checking if the info.plist file contains non-ASCII characters
if (Get-Content $plistPath -Encoding UTF8 | Select-String "[^\x00-\x7F]") {
    Write-Host "The $AppName info.plist contains non-ASCII (non-English) characters. Manually create application in Intune... Exiting." -ForegroundColor Red
    return
} else {
    Write-Host "The $AppName info.plist contains only ASCII (English) characters. Continuing..." -ForegroundColor Green
   
}
}

# Check if Info.plist exists
if (Test-Path $plistPath) {
    # Load the XML content of Info.plist
    [xml]$plist = Get-Content -Path $plistPath

    # Extract the dictionary node
    $dictNodes = $plist.plist.dict.ChildNodes

    # Initialize a dictionary to store key-value pairs
    $dict = @{}

    # Iterate through nodes to map keys to their respective values
    for ($i = 0; $i -lt $dictNodes.Count; $i++) {
        if ($dictNodes[$i].Name -eq "key") {
            $keyName = $dictNodes[$i].'#text'  # Extract key name
            if ($i + 1 -lt $dictNodes.Count -and $dictNodes[$i + 1].Name -eq "string") {
                $dict[$keyName] = $dictNodes[$i + 1].'#text'  # Extract corresponding string value
            }
        }
    }

    # Extract relevant application details
   # $appName = $]
    $appVersion = $dict["CFBundleShortVersionString"]
    $bundleID = $dict["CFBundleIdentifier"]
   } 
else 
{
    Write-Host "Info.plist file not found at the specified path." -ForegroundColor Red
    return 
}
}

#===============================================================================================================================================================================================#
# macOSPkgApp   #macOSDmgApp
$appType =         "macOSPkgApp"   
$appDisplayName =  "$appName"
$appDescription =  "$appName"
$appPublisher =    $Publisher
$appFilePath =     $SourceFile
$appHomepage =     $appHomepage
$appBundleId =     "$bundleID"
$appBundleVersion= "$appVersion"
$tempLogoPath =     $LogoFile

#===============================================================================================================================================================================================#
           
# Import required modules
Import-Module Microsoft.Graph.Authentication
$newFilePath = "$Source\$DownloadedFileName"
# Encrypts app file using AES encryption for Intune upload
function EncryptFile ($newFilePath) {
    function GenerateKey() {
        $aesSp = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aesSp.GenerateKey()
        return $aesSp.Key
    }

    $targetFile = "$Source\$DownloadedFileName.bin"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = GenerateKey
    $hmac = [System.Security.Cryptography.HMACSHA256]::new()
    $hmac.Key = GenerateKey
    $hashLength = $hmac.HashSize / 8
    $sourceStream = [System.IO.File]::OpenRead($newFilePath)
    $sourceSha256 = $sha256.ComputeHash($sourceStream)
    $sourceStream.Seek(0, "Begin") | Out-Null
    $targetStream = [System.IO.File]::Open($targetFile, "Create")
    $targetStream.Write((New-Object byte[] $hashLength), 0, $hashLength)
    $targetStream.Write($aes.IV, 0, $aes.IV.Length)
    $transform = $aes.CreateEncryptor()
    $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($targetStream, $transform, "Write")
    $sourceStream.CopyTo($cryptoStream)
    $cryptoStream.FlushFinalBlock()
    $targetStream.Seek($hashLength, "Begin") | Out-Null
    $mac = $hmac.ComputeHash($targetStream)
    $targetStream.Seek(0, "Begin") | Out-Null
    $targetStream.Write($mac, 0, $mac.Length)
    $targetStream.Close()
    $cryptoStream.Close()
    $sourceStream.Close()

    return [PSCustomObject][ordered]@{
        encryptionKey        = [System.Convert]::ToBase64String($aes.Key)
        fileDigest           = [System.Convert]::ToBase64String($sourceSha256)
        fileDigestAlgorithm  = "SHA256"
        initializationVector = [System.Convert]::ToBase64String($aes.IV)
        mac                  = [System.Convert]::ToBase64String($mac)
        macKey               = [System.Convert]::ToBase64String($hmac.Key)
        profileIdentifier    = "ProfileVersion1"
    }
}
#===============================================================================================================================================================================================#

# Function to upload file using AzCopy
$env:AZCOPY_LOG_LOCATION=$logPathAzCopy
function Upload-UsingAzCopy {
    param (
        [string]$fileToUpload, 
        [string]$destinationUri
    )
    if (!(Test-Path "$azCopyDirectory\azcopy.exe")) {
        Write-Host "AzCopy.exe not found. Please install AzCopy and try again." -ForegroundColor red
        return 
    }
    
    Write-Host "Using AzCopy.exe to upload file on Azure Blob" -ForegroundColor White
    & "$azCopyDirectory\azcopy.exe" copy $fileToUpload $destinationUri --recursive=true
    
    if ($?) {
        Write-Host "Application Content Upload successful on Azure Blob via AzCopy.exe" -ForegroundColor Green

    } else {
        Write-Host "Application Content Upload failed via AzCopy.exe"  -ForegroundColor Red
        return 
    }
}
Write-Host ""
#===============================================================================================================================================================================================#


# Prepare the application details
$PKGapp = @{ 
    "@odata.type"                   = "#microsoft.graph.$appType"
    displayName                     = $appDisplayName
    description                     = $appDescription
    publisher                       = $appPublisher
    fileName                        = $DownloadedFileName
    informationUrl                  = $appHomepage
    #packageIdentifier               = $appBundleId
    bundleId                        = $appBundleId
    versionNumber                   = $appBundleVersion
    minimumSupportedOperatingSystem = @{
        "@odata.type" = "#microsoft.graph.macOSMinimumOperatingSystem"
        v11_0         = $true
    }
}

if ($appType -eq "macOSPkgApp" ) 
{
    $PKGapp["primaryBundleId"] = $appBundleId
    $PKGapp["primaryBundleVersion"] = $appBundleVersion
    $PKGapp["includedApps"] = @(
        @{
            "@odata.type" = "#microsoft.graph.macOSIncludedApp"
            bundleId      = $appBundleId
            bundleVersion = $appBundleVersion
        }
    )
}

#Create app in Intune
Write-Host "Creating $appDisplayName Application In Intune Portal" -ForegroundColor Yellow
$createAppUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$newApp = Invoke-MgGraphRequest -Method POST -Uri $createAppUri -Body ($PKGapp | ConvertTo-Json -Depth 10)
Write-Host "$appDisplayName Application GUID is: $($newApp.id)" -ForegroundColor Green
#Write-Host "$appDisplayName Application metadata created successfully" -ForegroundColor Green
$contentVersionUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/microsoft.graph.$appType/contentVersions"
$contentVersion = Invoke-MgGraphRequest -Method POST -Uri $contentVersionUri -Body "{}"
Write-Host "$appDisplayName Application version: $($contentVersion.id)" -ForegroundColor Green
Write-Host "$appDisplayName CFBundleIdentifier is: $appBundleId" -ForegroundColor Green
Write-Host "$appDisplayName CFBundleShortVersionString is: $appBundleVersion" -ForegroundColor Green

# Encrypt the application file
Write-Host ""
Write-Host "Encrypting application file..." -ForegroundColor Yellow
$encryptedFilePath = "$Source\$DownloadedFileName.bin"
if (Test-Path $encryptedFilePath) {
    Remove-Item $encryptedFilePath -Force
}
$fileEncryptionInfo = EncryptFile $newFilePath 
Write-Host "Encryption complete" -ForegroundColor Green

# Upload to Azure Storage
Write-Host ""
Write-Host "Uploading to Azure Storage..." -ForegroundColor Yellow
$fileContent = @{
    "@odata.type" = "#microsoft.graph.mobileAppContentFile"
    name          = [System.IO.Path]::GetFileName($newFilePath)
    size          = (Get-Item $newFilePath).Length
    sizeEncrypted = (Get-Item "$newFilePath.bin").Length
    isDependency  = $false
}

$contentFileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/microsoft.graph.$appType/contentVersions/$($contentVersion.id)/files"  
$contentFile = Invoke-MgGraphRequest -Method POST -Uri $contentFileUri -Body ( $fileContent | ConvertTo-Json)

do {
    Start-Sleep -Seconds 5
    $fileStatusUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/microsoft.graph.$appType/contentVersions/$($contentVersion.id)/files/$($contentFile.id)"
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $fileStatusUri
} while ($fileStatus.uploadState -ne "azureStorageUriRequestSuccess")

# Always use AzCopy for upload
Write-Host "Uploading Application content using AzCopy.exe on Azure Blob" -ForegroundColor yellow
Write-Host ""
Upload-UsingAzCopy -fileToUpload "$newFilePath.bin" -destinationUri $fileStatus.azureStorageUri

#===============================================================================================================================================================================================#

# Commit the uploaded file
Write-Host ""
Write-Host "Start Committing file" -ForegroundColor Yellow
$commitData = @{
    fileEncryptionInfo = $fileEncryptionInfo
}
$commitUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/microsoft.graph.$appType/contentVersions/$($contentVersion.id)/files/$($contentFile.id)/commit"
Invoke-MgGraphRequest -Method POST -Uri $commitUri -Body ($commitData | ConvertTo-Json)

$retryCount = 0
$maxRetries = 2
do {
    Start-Sleep -Seconds 10
    $fileStatusUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/microsoft.graph.$appType/contentVersions/$($contentVersion.id)/files/$($contentFile.id)"
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $fileStatusUri
    if ($fileStatus.uploadState -eq "commitFileFailed") {
        $commitResponse = Invoke-MgGraphRequest -Method POST -Uri $commitUri -Body ($commitData | ConvertTo-Json)
        $retryCount++
    }
} while ($fileStatus.uploadState -ne "commitFileSuccess" -and $retryCount -lt $maxRetries)

if ($fileStatus.uploadState -eq "commitFileSuccess") {
   Write-Host "File committed successfully" -ForegroundColor Green
}
else {
    Write-Host "Failed to commit file after $maxRetries attempts."
    return 
}


# Update app with committed content version
$updateAppUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)"
$updateData = @{
    "@odata.type"           = "#microsoft.graph.$appType"
    committedContentVersion = $contentVersion.id
}
Invoke-MgGraphRequest -Method PATCH -Uri $updateAppUri -Body ($updateData | ConvertTo-Json)

#===============================================================================================================================================================================================#
# Updated/Uploaded application logo
Write-host ""
Write-Host "Updating/Uploading $appName logo" -ForegroundColor Yellow

# Convert the logo to base64
        $logoContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LogoFile))

        # Prepare the request body
        $logoBody = @{
            "@odata.type" = "#microsoft.graph.mimeContent"
            "type"        = "image/png"
            "value"       = $logoContent
        }

$logoUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)"
        $updateBody = @{
            "@odata.type" = "#microsoft.graph.$appType"
            "largeIcon"   = $logoBody
        }

Invoke-MgGraphRequest -Method PATCH -Uri $logoUri -Body ($updateBody | ConvertTo-Json -Depth 10)

Write-Host "Uploaded $appName logo" -ForegroundColor Green
Write-host ""
#===============================================================================================================================================================================================#

# Adding an application assignment using the Graph API...

Write-Host "Adding $appName application assignment......." -ForegroundColor Yellow

$ApiResource = "deviceAppManagement/mobileApps/$($newApp.id)/assign"

$RequestUri = "https://graph.microsoft.com/beta/$ApiResource"

# Validate inputs

if (-not ($($newApp.id))) 
 { 
 Write-Host "No Application Id specified" -ForegroundColor Red;
 return 
 }

if (-not $GroupID) 
 {
 Write-Host "No Target Group Id specified" -ForegroundColor Red; 
 return 
 }

if (-not $InstallMode) 
 {
 Write-Host "No Install Intent specified" -ForegroundColor Red;
 return  
 }

# JSON body

$JsonBody = @"
{
    "mobileAppAssignments": [
        {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$GroupID"
            },
            "intent": "$InstallMode"
        }
    ]
}
"@

# Invoke API request

try 
{
    Invoke-MgGraphRequest -Uri $RequestUri -Method Post -Body $JsonBody -ContentType "application/json"
}
 catch
  {
    $Exception = $_.Exception
 
    $ErrorResponse = $Exception.Response.GetResponseStream()
 
    $StreamReader = New-Object System.IO.StreamReader($ErrorResponse)
 
    $StreamReader.BaseStream.Position = 0
 
    $StreamReader.DiscardBufferedData()
 
    $ResponseContent = $StreamReader.ReadToEnd()
 
    Write-Host "Response content:`n$ResponseContent" -ForegroundColor Red
 
    Write-Error "Request to $RequestUri failed with HTTP Status $($Exception.Response.StatusCode) $($Exception.Response.StatusDescription)"
    
    return 

}

Write-Host "$appName macOS PKG application assigned successfully." -ForegroundColor Green
#===============================================================================================================================================================================================#
#Removing Working folders
Write-Host ""
Write-Host "Removing temporary files and folder" -ForegroundColor Yellow
$folders = @($MAC_PKG)
$folders | ForEach-Object { if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force } }
Write-Host "Removed temporary files and folder" -ForegroundColor Green
Write-Host ""
#===============================================================================================================================================================================================#
Write-Host ""


#Disconnect-MgGraph
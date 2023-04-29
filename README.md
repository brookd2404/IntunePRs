# Introduction
If it's your first time here, Welcome!, If you've returned, well then it's great to see you again, and the magic is really working 🤣.

This repository was started for session presentations as MMS (Midwest Management Summit) 2023. However, for the fruits of our labour we have decided to make a go of creating a high-quality repository for everyone to contribute to with some template, logging and magic!

If you missed our session at MMS, not to worry, there is always next year 😋, It runs the first week of May each year at the Mall of America, Bloomington, Minnesota.

## The T's & C's...

While we test these remediation's in our environments, we accept no responsibility for these being used in production at your organisation, and we thoroughly recommend you test, tailor and make them work for you. 

We aim to give you the magic bean, all you need to do is water it & make it grow to retrieve the harp and play your graceful tune!

<hr>

# Logging Functions

Inside the template, there are two functions which are aimed to improve the reporting functionality which is somewhat lacking for Proactive Remediation's. 

Described below, you can see the information relating to the functions, but if you are offline, and have not cloned the repository, do not fear as they are also in the Synopsis of the functions within the script.

## Start-Log
This function creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by **ConfigMgr** or **Autopatch**.
 

### **PARAMETER** LogName
```
The name of the log file to be created. If not specified, the name of the script will be used.
```
### **PARAMETER** LogFolder
```
The name of the folder to be created in the ProgramData directory to store the log file. If not specified, the default of Intune will be used.
```
### **PARAMETER** LogMaxSize
```
The maximum size in Mb of the log file before it is restarted. If not specified, the default of 10Mb will be used.
```

### Examples
   
```pwsh
# Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch.
Start-Log
```

```pwsh
#Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch with the name MyLog.log.
Start-Log -LogName "MyLog"

```
```pwsh
# Creates a log file in the CCM\Logs folder or in the ProgramData\MyFolder\Logs folder if the device is not managed by ConfigMgr or Autopatch with the name MyLog.log.
Start-Log -LogName "MyLog" -LogFolder "MyFolder"
```

## Write-Log
This function writes a message to the log file created with **Start-Log**. This uses various parameters which help make the logs more useful.


### **PARAMETER** Message
```
The message to be written to the log file.
```

### **PARAMETER** LogLevel

```
The level of the message to be written to the log file. Valid values are 1, 2, 3, Information, Warning, Error. Default is 1.
```

### **PARAMETER** Component
```
The component helps identify in the logs which component you are looking at.
```

### Examples

```pwsh
#Writes a message to the log file.
Write-Log -Message "This is a test message"
```

```pwsh
#Writes a message to the log file with a log level of 2 (Warning).
Write-Log -Message "This is a test message" -LogLevel 2
```

```pwsh
#Writes a message to the log file with a log level of 2 (Warning) marked as component Testing.
Write-Log -Message "This is a test message" -LogLevel 2 -Component "Testing"
```

# Contributions
We would love everyone in the community to commit to this repository with their Proactive Remediation's that are used across organisations you work with. 

However, that said, we want to keep a high standard of script submissions. Myself and [**Stevybsc**](https://github.com/StevyBSC) have created a Template file called [**PRTemplate.ps1**](/_Template/PRTemplate.ps1) which **MUST** be used as the base template. This script contains some core functions to make Logging easier, and readable in CMTrace and SupportCenter OneTrace. 

## Synopsis
Each Script should have a decent synopsis to ensure that admins can just pick it back out of the Intune Console and understand what it is doing.

## README's

Under the [**_Template**](/_Template/) folder, there is a README which should be submitted with your scripts to inform people the configuration desired for the Intune PR.

## Pull Requests
Pull Requests will be reviewed regularly, and the scripts will be tested and reviewed to ensure they deliver the cream for the cake!, please do not be disgruntled if we converse on the PR's and ask for things such as more logging, a desriptive synopsis etc, we just want to make sure everyone has what they need to succeed.

## Logging 
Soooo, there is no such thing as too much logging right? **Wrong**, I too have created a script previously, where the detection Log was over 15MB, so when the Remediation runs, it would clear the old log.

If this is the case, please add it to the notes at the top, and increase the log file size as appropriate.
<hr>

# Finding Us

You can also find Steve & I on twitter using the following links;
- Steve 
    - [**@StevyBSC - Twitter**](https://twitter.com/StevyBSC)
- David 
    - [**@DBBrook24 - Twitter**](https://twitter.com/DBBrook24)
    - [**EUC365 Blog**](https://euc365.com)
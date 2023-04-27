function Create-Chaos {
    param(
        [Parameter()]
        [array] $extensions = @(
            ".lnk",
            ".html",
            ".exe"
        ),
        [Parameter()]
        [array]$contains = @(
            $env:COMPUTERNAME,
            "Copy",
            "(1)"
        ),
        [Parameter()]
        [array]
        $sampleIncludes = @(
            "Microsoft Edge",
            "Teams",
            "Microsoft Office",
            "Microsoft Excel",
            "Microsoft Word",
            "Microsoft PowerPoint",
            "Microsoft Outlook",
            "Microsoft OneNote",
            "Microsoft Publisher",
            "Microsoft Access",
            "Microsoft Visio",
            "Microsoft Project",
            "Microsoft OneDrive",
            "Microsoft Skype",
            "Microsoft Yammer",
            "Microsoft SharePoint",
            "Microsoft Sway",
            "Microsoft Stream",
            "Microsoft To-Do",
            "Microsoft Planner",
            "Microsoft Whiteboard",
            "Microsoft Power BI",
            "Microsoft Dynamics 365",
            "Microsoft Power Automate",
            "Microsoft Power Apps",
            "Microsoft Azure"
        ),
        [Parameter()]
        [string]$desktopPath = (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").Desktop
    )

    #Create a desktop icon for each sampleIncludes with an extension from extensions and a contains from contains
    foreach ($sampleInclude in $sampleIncludes) {
        foreach ($extension in $extensions) {
            IF (-not([System.String]::IsNullOrWhiteSpace($extension))) {
                $fileBaseName = "$sampleInclude$extension"
                $fileBasePath = "$desktopPath\$fileBaseName"
                IF (-Not(Test-Path -Path $fileBasePath)) {
                    New-Item -Path $fileBasePath -ItemType File -Force
                }
                foreach ($contain in $contains) {
                    $fileName = "$sampleInclude $contain$extension"
                    $filePath = "$desktopPath\$fileName"
                    IF (-Not(Test-Path -Path $filePath)) {
                        New-Item -Path $filePath -ItemType File -Force
                    }
                }
            }
        }
    }
}

Create-Chaos
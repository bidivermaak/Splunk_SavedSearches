[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'

# Get event descriptions from workbook
$content_eventdesc = "$env:temp\tmpEventDescriptions.csv"
if (Test-Path -path $content_eventdesc)  { Remove-Item -Path $content_eventdesc -Force }
$source = "https://raw.githubusercontent.com/dstaulcu/Splunk_SavedSearches/master/resources/Windows%208%20and%20Windows%20Server%202012%20Security%20Event%20Descriptions.csv"
$Filename = [System.IO.Path]::GetFileName($source)
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($source, $content_eventdesc)
$content_eventdesc = Import-Csv -Path $content_eventdesc
 
# download list of searches
$WebResponse = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dstaulcu/Splunk_SavedSearches/master/savedsearches.conf"
if ($WebResponse.StatusDescription -ne "OK") {
    write-host "Unexpected response to web request. Exiting."
    exit
}

# assuming this is the content I expect...
# break the content on lines starting with "["
$lines = $WebResponse.RawContent -split "\["
$lines = $lines[1..$lines.Length]

$counter = 0
$SavedSearches=@()

foreach ($line in $lines) {

    # munge the data
    $line = "[$($line)"  
    $line = $line.trim()

    # extract eventcode  ## todo:  sourcetype
    $EventCode = (([regex]"(?i)EventCode\s*=\s*`"?(\d+)`"?").match($line).Groups[1].Value).trim()
    $SourceType = (([regex]"(?i)sourcetype\s*=\s*`"?(\S+)`"?").match($line).Groups[1].Value).Trim()
    $SourceType = $sourcetype -replace "`"",""
    $EventCode = $EventCode -replace "`"",""

    # add the stanza and event code to an object
    $CustomEvent = New-Object -TypeName PSObject
    $CustomEvent | Add-member -Type NoteProperty -Name 'Search' -Value $line -ErrorAction SilentlyContinue -Force
    $CustomEvent | Add-member -Type NoteProperty -Name 'EventCode' -Value $EventCode -ErrorAction SilentlyContinue -Force
    $CustomEvent | Add-member -Type NoteProperty -Name 'SourceType' -Value $SourceType -ErrorAction SilentlyContinue -Force

    # append the object to a list object
    $SavedSearches += $CustomEvent

}


$content_savedsearches = "$env:temp\tmpSavedSearches.txt"
if (Test-Path -path $content_savedsearches)  { Remove-Item -Path $content_savedsearches -Force }

foreach ($item in $content_eventdesc) {
    $search = "`n[$($item.Category):$($item.SubCategory):$($item.'Event ID') - $($item.'Message Summary')]`nsearch = sourcetype=`"WinEventLog:Security`" EventCode=`"$($item.'Event ID')`"`n"

    $MatchingSearch = $savedsearches | where-object {$_.EventCode -eq $item.'event id'}
    if (!($MatchingSearch)) {
        $search += "| TODO"
    } else {
        $matchingsearchdata = ($MatchingSearch.search -split "EventCode\s*=\s*`"?\d+`"?\s*")[1]
        $search += "$($matchingsearchdata)"
    }

    Add-Content -Path $content_savedsearches -Value "$($search)"
}

Get-Content -Path $content_savedsearches | clip
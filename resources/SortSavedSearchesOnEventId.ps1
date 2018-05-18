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

# sort the list object by event code
# print the ordered results (to clipboard)
# paste clipboard back into github

$SavedSearches = $SavedSearches | Sort-Object -Property SourceType, EventCode 

$content = "$env:temp\tmpfile.txt"
if (Test-Path -path $content)  { Remove-Item -Path $content -Force }

foreach ($search in $SavedSearches) {
    write-host "$($search.sourcetype):$($search.EventCode)"
    Add-Content -Path $content -Value "`n$($search.search)"
}

Get-Content -Path $content | clip

$transforms = "$env:temp\transforms.conf"
$props = "$env:temp\props.conf"
if (Test-Path -Path $transforms) { Remove-Item -Path $transforms -Force }
if (Test-Path -Path $props) { Remove-Item -Path $props -Force }


$WebResponse = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dstaulcu/Splunk_SavedSearches/master/savedsearches.conf" -Headers @{"Cache-Control"="no-cache"}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'


if ($WebResponse.StatusDescription -ne "OK") {
    write-host "Unexpected response to web request. Exiting."
    exit
}

# assuming this is the content I expect...
# break the content on lines starting with "["
$lines = $WebResponse.content -split "`n"
$lines = $lines | Select-String -Pattern "\|\s+rex\s+"
$lines

$Patterns =@()

foreach ($line in $lines) {
    $Patterns += (($line).tostring()).trim()
}

# get the unique patterns from the result set
$expressions = $Patterns | Select-Object -Unique | Sort-Object
$expressions


<#
# List all the tokens for human review 
$tokens = $Patterns | select-string -pattern '(?smi)(<(\w+)>)' -AllMatches | Foreach {$_.Matches} | ForEach-Object {$_.Value}
$tokens = $tokens -replace "(<|>)",""
$tokenList = $tokens | Group-Object | Sort-Object -Property Name -Descending | select-object Count, Name
foreach ($token in $tokenList) {
    if ($token.name.length -gt 32) {
        $howmanytocut = $token.name.length - 32
        write-host "$($token.name) is $($token.name.length) char log.  Please cut $($howmanytocut)!"
    }
}
#>

$count = 0
$reports = ""
foreach ($expression in $expressions) {

    $expression = $expression -replace "\s*\|\s*rex\s+",""
    $matches = $expression | select-string -pattern '(?smi)(<(\w+)>)' -AllMatches | Foreach {$_.Matches} | ForEach-Object {$_.Value}
    $matches | %{$expression = $expression -replace "\?$($_)",""}

    $formatcontent = ""
    $formatcontent_count = 1
    foreach ($match in $matches)  {
        $match = $match -replace "\<|\>",""
        if (!($formatcontent)) {
            $formatcontent = "$($match)::`$$($formatcontent_count)"
        } else {
            $formatcontent += " $($match)::`$$($formatcontent_count)"
        }
        $formatcontent_count++
    }

    $expression = $expression.trim() -replace "(^`"|`"$)",""
    $count++


    $report = "wineventlog_security_extraction_$($count)"
    if (!($reports)) {
        $reports = $report       
    } else {
        $reports = "$($reports), $($report)"
    }

    Add-Content -Path $transforms -Value "`n#$($expression)"   
    Add-Content -Path $transforms -Value "[$($report)]"
    Add-Content -Path $transforms -Value "SOURCE_KEY = _raw"
    Add-Content -Path $transforms -Value "REGEX = $($expression)"  
    Add-Content -Path $transforms -Value "FORMAT = $($formatcontent)"

}

add-content -Path $props -value "`n"
add-content -Path $props -value "###### Windows Security Event Log ######"
add-content -Path $props -value "[source::WinEventLog:Security]"
add-content -Path $props -value "REPORT-wineventlog_security_extractions = $($reports)"


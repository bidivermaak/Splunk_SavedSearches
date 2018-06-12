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
$lines = $WebResponse.RawContent -split "\["
$lines = $lines[1..$lines.Length]

$patterns=@()

# get the regular expression patterns from the web response ( content of savedsearches.conf on github )
foreach ($line in $lines) {
    if ($line -match "search =") {
        $line = $line -split ("\|")
        $lines = ($line | Select-String -Pattern "rex\s+")
        foreach ($line in $lines) {
            $Patterns += (($line).tostring()).trim()
        }
        
    }
}

# get the unique patterns from the result set
$expressions = $Patterns | Select-Object -Unique | Sort-Object

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

    $expression = $expression -replace "\s*rex\s+",""
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
    
    Add-Content -Path $transforms -Value "`n[$($report)]"
    Add-Content -Path $transforms -Value "SOURCE_KEY = _raw"
    Add-Content -Path $transforms -Value "REGEX = $($expression)"  
    Add-Content -Path $transforms -Value "FORMAT = $($formatcontent)"

}

add-content -Path $props -value "`nREPORT-wineventlog_security_extractions = $($reports)"


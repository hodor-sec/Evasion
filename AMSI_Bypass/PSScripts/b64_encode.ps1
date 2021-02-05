function toBase64{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $InFile,
        [Parameter(Mandatory=$false, Position=1)]
        [string] $OutFile
    )
    $Content = Get-Content -Path $InFile -Encoding Byte
    $b64 = [System.Convert]::ToBase64String($Content)
    if($OutFile -eq ""){
        return $b64
    }
    else {
        Write-Host "Writing b64 encoded file to $OutFile"
        $b64 | Out-File $OutFile
    }
}

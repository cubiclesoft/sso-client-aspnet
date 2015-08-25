*************************** SSO Client for ASP.NET ***************************

The SSO client for ASP.NET is written in C#.  Due to the nature of ASP.NET,
the client is intended to be the basis of a new ASP.NET application rather
than trying to integrate existing infrastructure with it.

Upload the files to its own directory and launch a web browser and point it
at the directory.  It should detect that the client has not been installed and
redirect to the installer.  It is advisable on public machines to lock down
the 'SSO_Client_Install.aspx' page by editing 'SSO_Client_Install.aspx.cs'
before uploading the files.

The ASP.NET SSO client aims to be almost identical to the PHP SSO client.
However, there are notable differences:

  - Only AES-256 API keys and data storage may be used.  Blowfish is not
    available.

  - Complete integration requires not using 'Request.QueryString',
    'Request.Forms', or 'Request.Cookies'.  Equivalents that are read/write
    are exposed via 'SSO.Client.Manager.Instance'.

The 'App_Code\SSO_Client_Application' file is meant to be modified to handle
whatever the needs to work properly.  It is similar to 'test_oo.php'.

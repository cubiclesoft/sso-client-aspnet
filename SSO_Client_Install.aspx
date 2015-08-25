<%@ Page Language="C#" AutoEventWireup="true" CodeFile="SSO_Client_Install.aspx.cs" Inherits="SSO_Client_Install" %>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
<title>Single Sign-On Client Installer</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<link rel="stylesheet" href="support/install.css" type="text/css" />
<script type="text/javascript" src="support/jquery-1.11.0.min.js"></script>

<script type="text/javascript">
    function Page(curr, next) {
        $('#page' + curr).hide();
        $('#page' + next).fadeIn('normal');

        return false;
    }
</script>

</head>
<body>
<noscript><span class="error">Er...  You need Javascript enabled to install Single Sign-On (SSO) Client.</span></noscript>
<form id="installform" method="post" enctype="multipart/form-data" action="SSO_Client_Install.aspx" accept-charset="utf-8">
<input type="hidden" name="action" value="install" />
<div id="main">
	<div id="page1" class="box">
		<h1>Single Sign-On Client Installer</h1>
		<h3>Welcome to the Single Sign-On Client installer.</h3>
		<div class="boxmain">
			If you are looking to implement a centralized account management and login system for one or more domains,
			bring disparate login systems together under a unified system, and easily manage all aspects of a user account,
			then this is most likely what you are looking for:<br /><br />

			<div class="indent">
				A self-contained, centralized account management server that can sit on any domain with tools
				to easily manage user fields and access permissions, with multiple signup and sign in options,
				and easy-to-use client functions to sign in and extract information from the server in a
				secure manner.  Or more simply put:  Do you need a login system that rocks?
			</div>
			<br />

			If that sounds like you, Single Sign-On (SSO) is the answer.  Just click "Next" below to get started.
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(1, 2);">Next &raquo;</a>
		</div>
	</div>

	<div id="page2" class="box" style="display: none;">
		<h1>Single Sign-On Client Requirements</h1>
		<h3>The Single Sign-On Client system requirements.</h3>
		<div class="boxmain">
			In order to use Single Sign-On (SSO) Client, you will need to meet these logistical requirements:<br />
			<ul>
				<li>Someone who knows ASP.NET (a ASP.NET programmer)</li>
			</ul>

			You will also need to meet these technical requirements (most of these are auto-detected by this installation wizard):<br />
			<ul>
				<li><a href="http://www.asp.net/" target="_blank">ASP.NET</a> (preferably the latest)</li>
				<li><a href="http://barebonescms.com/documentation/sso/" target="_blank">A valid Single Sign-On (SSO) Server API key and secret</a></li>
			</ul>
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(2, 1);">&laquo; Prev</a> | <a href="#" onclick="return Page(2, 3);">Next &raquo;</a>
		</div>
	</div>

	<div id="page3" class="box" style="display: none;">
		<h1>Single Sign-On Client Checklist</h1>
		<h3>The Single Sign-On Client compatability checklist.</h3>
		<div class="boxmain">
			Before beginning the installation, you should check to make sure that the server meets or exceeds
			the basic technical requirements.  Below is the checklist for compatability with Single Sign-On (SSO) Client.<br /><br />

			<div id="checklist"></div>
			<br />

			<script type="text/javascript">
			    function RefreshChecklist() {
			        $.ajax({
			            type: "POST",
			            url: "SSO_Client_Install.aspx/Ajax_checklist",
			            beforeSend: function (xhr) {
                            xhr.setRequestHeader("Content-type", "application/json; charset=utf-8");
			            },
			            dataType: "json",
			            success: function (msg) {
			                $('#checklist').html(msg.d);
			            }
			        });

			        return false;
			    }

			    RefreshChecklist();
			</script>

			<a href="#" onclick="return RefreshChecklist();">Refresh the checklist</a><br /><br />

			NOTE:  You are allowed to install Single Sign-On (SSO) Client even if you don't meet the requirements above.  Just don't complain if your
			installation or this installer does not work.  Each web server is different - there is no way to satisfy all servers
			without a ton of code.  Besides, you may be able to get away with some missing things for some websites.
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(3, 2);">&laquo; Prev</a> | <a href="#" onclick="return Page(3, 4);">Next &raquo;</a>
		</div>
	</div>

	<div id="page4" class="box" style="display: none;">
		<h1>Single Sign-On Client Setup</h1>
		<h3>Set up Single Sign-On (SSO) Client options.</h3>
		<div class="boxmain">
			Set up the Single Sign-On (SSO) Client base options.<br /><br />

			<div class="formfields">
				<div class="formitem">
					<div class="formitemtitle">Trusted 'X-Forwarded-For' Proxies</div>
					<input class="text" id="sso_proxy_x_forwarded_for" type="text" name="sso_proxy_x_forwarded_for" value="" />
					<div class="formitemdesc">A semi-colon separated list of IP addresses of trusted proxy servers that put the remote address into a 'X-Forwarded-For' HTTP header.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Trusted 'Client-IP' Proxies</div>
					<input class="text" id="sso_proxy_client_ip" type="text" name="sso_proxy_client_ip" value="" />
					<div class="formitemdesc">A semi-colon separated list of IP addresses of trusted proxy servers that put the remote address into a 'Client-IP' HTTP header.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Name</div>
					<input class="text" id="sso_cookie_name" type="text" name="sso_cookie_name" value="<% Response.Write(HttpUtility.HtmlEncode(HttpContext.Current.Request.QueryString["cookie_name"] != null ? HttpContext.Current.Request.QueryString["cookie_name"] : "sso_")); %>" />
					<div class="formitemdesc">The name of the session cookie to use in the web browser for this SSO Client instance.  There should be one SSO Client instance per application.  Valid characters are A-Z, a-z, 0-9, and underscore '_'.</div>
				</div>
<%
        string URL = HttpContext.Current.Request.Path;
        int Pos = URL.LastIndexOf('/');
        if (Pos < 0)  URL = "/";
        else  URL = URL.Substring(0, Pos + 1);
%>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Path</div>
					<input class="text" id="sso_cookie_path" type="text" name="sso_cookie_path" value="<% Response.Write(HttpUtility.HtmlEncode(HttpContext.Current.Request.QueryString["cookie_path"] != null ? HttpContext.Current.Request.QueryString["cookie_path"] : URL)); %>" />
					<div class="formitemdesc">The base path where the SSO Client cookie will be applicable.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Timeout</div>
					<input class="text" id="sso_cookie_timeout" type="text" name="sso_cookie_timeout" value="<% Response.Write(HttpUtility.HtmlEncode(HttpContext.Current.Request.QueryString["cookie_timeout"] != null ? HttpContext.Current.Request.QueryString["cookie_timeout"] : "0")); %>" />
					<div class="formitemdesc">How long the SSO Client cookie lives before it expires (in seconds).  A value of zero keeps the cookie until the browser is closed.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Exit Timeout?</div>
					<select id="sso_cookie_exit_timeout" name="sso_cookie_exit_timeout">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled and SSO Client Cookie Timeout is non-zero, the cookie information will also expire when the browser is closed, whichever comes first.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie over SSL only?</div>
					<select id="sso_cookie_ssl_only" name="sso_cookie_ssl_only">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the session information will only be sent over SSL connections.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Resets on IP Address Changes?</div>
					<select id="sso_cookie_reset_ipaddr_changes" name="sso_cookie_reset_ipaddr_changes">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the session information will be reset and the user forced to sign in again if their IP address changes.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Validation Check</div>
					<input class="text" id="sso_cookie_check" type="text" name="sso_cookie_check" value="300" />
					<div class="formitemdesc">How long the SSO Client cookie data is valid for, in seconds, before the client needs to check with the SSO Server again.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server Endpoint URL</div>
					<input class="text" id="sso_server_endpoint_url" type="text" name="sso_server_endpoint_url" value="" />
					<div class="formitemdesc">The Endpoint URL to use from the SSO Server.  This may be obtained by logging into the SSO Server and going into 'Manage API Keys'.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server API Key</div>
					<input class="text" id="sso_server_apikey" type="text" name="sso_server_apikey" value="" />
					<div class="formitemdesc">The API key for this client instance.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server Secret Key</div>
					<input class="text" id="sso_server_secretkey" type="text" name="sso_server_secretkey" value="" />
					<div class="formitemdesc">The secret key for the API key.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server Session Timeout</div>
					<input class="text" id="sso_server_session_timeout" type="text" name="sso_server_session_timeout" value="604800" />
					<div class="formitemdesc">How long the SSO Server session data is valid for without a successful SSO Client Validation Check (in seconds).  Five minutes (300 seconds) is the minimum the server supports.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Accepts Site Admin?</div>
					<select id="sso_accept_site_admin" name="sso_accept_site_admin">
						<option value="1">Yes</option>
						<option value="0">No</option>
					</select>
					<div class="formitemdesc">When enabled, the SSO client will return true for SSO_IsSiteAdmin() when a signed in site admin visits.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Checks Site Admin?</div>
					<select id="sso_check_site_admin" name="sso_check_site_admin">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the SSO client will always check with the SSO server whenever a signed in site admin visits.</div>
				</div>
			</div>
			<br />

			<div id="baseoptstestwrap" class="testresult">
				<div id="baseoptstest"></div>
			</div>
			<br />

			<script type="text/javascript">
			    function RefreshBaseOptsTest() {
			        $('#baseoptstestwrap').fadeIn('slow');
			        $.ajax({
			            type: "POST",
			            url: "SSO_Client_Install.aspx/Ajax_baseoptstest",
			            beforeSend: function (xhr) {
			                xhr.setRequestHeader("Content-type", "application/json; charset=utf-8");
			            },
			            dataType: "json",
			            data: JSON.stringify({
			                'cookie_name': $('#sso_cookie_name').val(),
			                'cookie_path': $('#sso_cookie_path').val(),
			                'url': $('#sso_server_endpoint_url').val(),
			                'apikey': $('#sso_server_apikey').val(),
			                'secretkey': $('#sso_server_secretkey').val(),
			                'sso_proxy_x_forwarded_for': $('#sso_proxy_x_forwarded_for').val(),
			                'sso_proxy_client_ip': $('#sso_proxy_client_ip').val()
			            }),
			            success: function (msg) {
			                $('#baseoptstest').html(msg.d);
			            }
			        });

			        return false;
			    }
			</script>

			<a href="#" onclick="return RefreshBaseOptsTest();">Test the base options</a><br /><br />
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(4, 3);">&laquo; Prev</a> | <a href="#" onclick="return Page(4, 5);">Next &raquo;</a>
		</div>
	</div>

	<div id="page5" class="box" style="display: none;">
		<h1>Ready To Install</h1>
		<h3>Ready to install Single Sign-On Client.</h3>
		<div class="boxmain">
			Single Sign-On Client is ready to install.  Click the link below to complete the installation process.
			Upon successful completion, 'install.php' (this installer) will be disabled.
			NOTE:  Be patient during the installation process.  It takes 5 to 30 seconds to complete.<br /><br />

			<div id="installwrap" class="testresult">
				<div id="install"></div>
			</div>
			<br />

			<script type="text/javascript">
			    function Install() {
			        $('#installlink').hide();
			        $('.boxbuttons').hide();
			        $('#installwrap').fadeIn('slow');
			        var installvars = {};
			        $('input').each(function() { installvars[this.name] = this.value; });
			        $('select').each(function() { installvars[this.name] = this.value; });

			        $.ajax({
			            type: "POST",
			            url: "SSO_Client_Install.aspx/Ajax_install",
			            beforeSend: function (xhr) {
			                xhr.setRequestHeader("Content-type", "application/json; charset=utf-8");
			            },
			            dataType: "json",
			            data: JSON.stringify(installvars),
			            success: function (msg) {
			                $('#install').html(msg.d);
			            }
			        });

			        return false;
			    }

			    function InstallFailed() {
			        $('#installlink').fadeIn('slow');
			        $('.boxbuttons').fadeIn('slow');
			    }
			</script>

			<a id="installlink" href="#" onclick="return Install();">Install Single Sign-On Client</a><br /><br />
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(5, 4);">&laquo; Prev</a>
		</div>
	</div>

</div>
</form>
</body>
</html>

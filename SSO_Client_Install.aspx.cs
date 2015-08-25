// Single Sign-On client installer for ASP.NET.
// (C) 2014 CubicleSoft.  All Rights Reserved.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Services;
using System.Web.UI;
using System.Web.UI.WebControls;

public partial class SSO_Client_Install : System.Web.UI.Page
{
    public static void RestrictAccess()
    {
        // Put your logic here to restrict access to the installer.
        //if (HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"] == "127.0.0.1")  HttpContext.Current.Response.Redirect("AccessDenied.html");
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        RestrictAccess();

        SSO.Client.Manager AppManager = SSO.Client.Manager.Instance;

        if (AppManager.IsInstalled())  Response.Redirect("Default.aspx");

        // Make sure the configuration file is not read-only.
        var ConfigPath = Server.MapPath("~/web.config");
        var Attrs = File.GetAttributes(ConfigPath);
        if ((Attrs & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
        {
            Attrs = Attrs & ~FileAttributes.ReadOnly;
            File.SetAttributes(ConfigPath, Attrs);
        }
    }

    [WebMethod]
    public static string Ajax_checklist()
    {
        RestrictAccess();

        SSO.Client.Manager AppManager = SSO.Client.Manager.Instance;

        if (AppManager.IsInstalled())  return "";

        string Result = "";

        Result += "<table align=\"center\">\n";
        Result += "<tr class=\"head\"><th>Test</th><th>Passed?</th></tr>\n";
        Result += "<tr class=\"row altrow\">\n";
        Result += "<td>Installation over SSL</td>\n";
        Result += "<td align=\"right\">\n";
        if (!HttpContext.Current.Request.IsSecureConnection) Result += "<span class=\"error\">No</span><br /><br />While Single Sign-On Client will install and run without using HTTPS/SSL, think about the implications of network sniffing access tokens, who will have access to the system, and what they can do in the system.  SSL certificates can be obtained for free.  Proceed only if this major security risk is acceptable.";
        else  Result += "<span class=\"success\">Yes</span>";
        Result += "</td>\n";
        Result += "</tr>\n";
        Result += "</table>\n";

        return Result;
    }

    [WebMethod]
    public static string Ajax_baseoptstest(string cookie_name, string cookie_path, string sso_proxy_x_forwarded_for, string sso_proxy_client_ip, string url, string apikey, string secretkey)
    {
        RestrictAccess();

        SSO.Client.Manager AppManager = SSO.Client.Manager.Instance;

        if (AppManager.IsInstalled())  return "";

        string Result = "";
        string CookieName2 = Regex.Replace(Regex.Replace(cookie_name, "/[^A-Za-z0-9]/", " ").Trim(), "/\\s+/", "_");

        if (cookie_name == "")  Result += "<span class=\"error\">'SSO Client Cookie Name' must not be empty or use invalid characters.</span><br />";
        else if (cookie_name == "sso_")  Result += "<span class=\"warning\">'SSO Client Cookie Name' is set to the default name.  You should consider making it specific to your application.</span><br />";
        else if (cookie_name == "sso_server")  Result += "<span class=\"error\">'SSO Client Cookie Name' is set to a reserved name that may cause problems.</span><br />";
		else if (CookieName2 != cookie_name)  Result += "<span class=\"warning\">'SSO Client Cookie Name' will evaluate to '" + HttpUtility.HtmlEncode(cookie_name) + "'.  This may not be what you entered or produce unintentional results.</span><br />";
		else if (cookie_path.Substring(cookie_path.Length - 1) != "/")  Result += "<span class=\"error\">'SSO Client Cookie Path' does not have a trailing '/' character.  This can cause problems in some browsers.</span><br />";
		else  Result += "<span class=\"success\">The cookie information looks okay.</span><br />";

        AppManager.SetConfigOption("proxy_x_forwarded_for", sso_proxy_x_forwarded_for);
        AppManager.SetConfigOption("proxy_client_ip", sso_proxy_client_ip);
        AppManager.SetConfigOption("server_endpoint_url", url);
        AppManager.SetConfigOption("server_apikey", apikey);
        AppManager.SetConfigOption("server_secretkey", secretkey);

        if (url == "")  Result += "<span class=\"error\">'SSO Server Endpoint URL' is empty.</span><br />";
        else if (apikey == "")  Result += "<span class=\"error\">'SSO Server API Key' is empty.</span><br />";
        else if (secretkey == "")  Result += "<span class=\"error\">'SSO Server Secret Key' is empty.</span><br />";
        else
        {
            try
            {
                JObject TempResult = AppManager.SendRequest("test", null);
                if ((bool)TempResult["success"])  Result += "<span class=\"success\">Successfully connected to the SSO server.</span><br />";
                else  Result += "<span class=\"error\">Connected to the SSO server but the server encountered an error.  Error:  " + HttpUtility.HtmlEncode((string)TempResult["error"]) + "</span><br />";
            }
            catch (SSO.Client.SSOException e)
            {
			    Result += "<span class=\"error\">Failed to connect to the SSO server.  Error:  " + HttpUtility.HtmlEncode(e.Message) + "</span><br />";
            }
        }

        return Result;
    }

    [WebMethod]
    public static string Ajax_install(string sso_proxy_x_forwarded_for, string sso_proxy_client_ip, string sso_cookie_name, string sso_cookie_path, string sso_cookie_timeout, string sso_cookie_exit_timeout, string sso_cookie_ssl_only, string sso_cookie_reset_ipaddr_changes, string sso_cookie_check, string sso_server_endpoint_url, string sso_server_apikey, string sso_server_secretkey, string sso_server_session_timeout, string sso_accept_site_admin, string sso_check_site_admin)
    {
        RestrictAccess();

        SSO.Client.Manager AppManager = SSO.Client.Manager.Instance;

        if (AppManager.IsInstalled())  return "";

        string Result = "";

		if (sso_cookie_path.Substring(sso_cookie_path.Length - 1) != "/")  return InstallError(Result, "'SSO Client Cookie Path' does not have a trailing '/' character.  This can cause problems in some browsers.");

        string CookieName2 = Regex.Replace(Regex.Replace(sso_cookie_name, "/[^A-Za-z0-9]/", " ").Trim(), "/\\s+/", "_");

		if (CookieName2 == "")  return InstallError(Result, "'SSO Client Cookie Name' must not be empty or use invalid characters.");
		else if (CookieName2 == "sso_")  Result = InstallWarning(Result, "'SSO Client Cookie Name' is set to the default name.  You should consider reinstalling the SSO Client and making it specific to your application.");
		else if (CookieName2 == "sso_server")  return InstallError(Result, "'SSO Client Cookie Name' is set to a reserved name that may cause problems.");

		if (Convert.ToInt32(sso_cookie_timeout) < 0)  return InstallError(Result, "'SSO Client Cookie Timeout' is less than 0.");
		if (Convert.ToInt32(sso_cookie_check) < 0)  return InstallError(Result, "'SSO Client Cookie Validation Check' is less than 0.");
		if (Convert.ToInt32(sso_server_session_timeout) < 0)  return InstallError(Result, "'SSO Server Session Timeout' is less than 0.");
		if (Convert.ToInt32(sso_server_session_timeout) < Convert.ToInt32(sso_cookie_check))  return InstallError(Result, "'SSO Server Session Timeout' is less than 'SSO Client Cookie Validation Check'.");
		if (Convert.ToInt32(sso_cookie_timeout) > 0 && Convert.ToInt32(sso_server_session_timeout) > Convert.ToInt32(sso_cookie_timeout))  return InstallError(Result, "'SSO Server Session Timeout' is greater than 'SSO Client Cookie Timeout'.");
		if (sso_server_endpoint_url == "")  return InstallError(Result, "'SSO Server Endpoint URL' is empty.");
		if (sso_server_apikey == "")  return InstallError(Result, "'SSO Server API Key' is empty.");
		if (sso_server_secretkey == "")  return InstallError(Result, "'SSO Server Secret Key' is empty.");

        AppManager.SetConfigOption("proxy_x_forwarded_for", sso_proxy_x_forwarded_for);
        AppManager.SetConfigOption("proxy_client_ip", sso_proxy_client_ip);
        AppManager.SetConfigOption("cookie_name", CookieName2);
        AppManager.SetConfigOption("cookie_path", sso_cookie_path);
        AppManager.SetConfigOption("cookie_timeout", sso_cookie_timeout);
        AppManager.SetConfigOption("cookie_exit_timeout", sso_cookie_exit_timeout);
        AppManager.SetConfigOption("cookie_ssl_only", sso_cookie_ssl_only);
        AppManager.SetConfigOption("cookie_reset_ipaddr_changes", sso_cookie_reset_ipaddr_changes);
        AppManager.SetConfigOption("cookie_check", sso_cookie_check);
        AppManager.SetConfigOption("server_endpoint_url", sso_server_endpoint_url);
        AppManager.SetConfigOption("server_apikey", sso_server_apikey);
        AppManager.SetConfigOption("server_secretkey", sso_server_secretkey);
        AppManager.SetConfigOption("server_session_timeout", sso_server_session_timeout);
        AppManager.SetConfigOption("accept_site_admin", sso_accept_site_admin);
        AppManager.SetConfigOption("check_site_admin", sso_check_site_admin);
        AppManager.SetConfigOption("rand_seed", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed2", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed3", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed4", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed5", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed6", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed7", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed8", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed9", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed10", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed11", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed12", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed13", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed14", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed15", AppManager.GenerateToken(128));
        AppManager.SetConfigOption("rand_seed16", AppManager.GenerateToken(128));
        AppManager.SaveConfiguration();
        Result = InstallSuccess(Result, "Successfully saved the configuration.");

        Result = InstallSuccess(Result, "The installation completed successfully.");

        Result += "<br />";
        Result += "Next:  Start using Single-Sign On Client<br />";
        Result += "(Follow the <a href=\"http://barebonescms.com/documentation/sso/\">instructions</a> to learn how to use the SSO Client.)<br />";

        return Result;
    }

    private static string InstallError(string Result, string Message)
    {
        Result += "<span class=\"error\">" + Message + "  Click 'Prev' below to go back and correct the problem.</span>";
        Result += "<script type=\"text/javascript\">InstallFailed();</script>";

        return Result;
    }

    private static string InstallWarning(string Result, string Message)
    {
        Result += "<span class=\"warning\">" + Message + "</span><br />";

        return Result;
    }

    private static string InstallSuccess(string Result, string Message)
    {
        Result += "<span class=\"success\">" + Message + "</span><br />";

        return Result;
    }
}

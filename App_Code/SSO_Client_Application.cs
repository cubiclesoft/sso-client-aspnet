using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;

namespace SSO.Client
{
    /// <summary>
    /// Main application interface to the Manager.
    /// Intended to be customized for the application by the user of the SSO client.
    /// </summary>
    public class Application
    {
        public static void Init()
        {
            SSO.Client.Manager AppManager = SSO.Client.Manager.Instance;

            // Make sure the application is installed.
            if (!AppManager.IsInstalled())  HttpContext.Current.Response.Redirect("SSO_Client_Install.aspx");

            // Initialize the SSO client.
            AppManager.Init(new string[] { "sso_impersonate", "sso_remote_id" });

            NameValueCollection Extra = new NameValueCollection();
            if (AppManager.RequestVars["sso_impersonate"] != null)  Extra["sso_impersonate"] = AppManager.RequestVars["sso_impersonate"];
            else if (AppManager.RequestVars["sso_remote_id"] != null)
            {
                Extra["sso_provider"] = "sso_remote";
                Extra["sso_remote_id"] = AppManager.RequestVars["sso_remote_id"];
            }
            if (!AppManager.LoggedIn())  AppManager.Login("", "", Extra);

            if (!AppManager.UserLoaded())
            {
                // Load local information from the encrypted cookie.
                string Username = AppManager.GetData("u");
                string Firstname = AppManager.GetData("fn");
                string Lastname = AppManager.GetData("ln");

                // If the cookie data is too long, false will be returned, so load the official data.
                if (Username == null || Firstname == null || Lastname == null)
                {
                    if (!AppManager.LoadUserInfo())  throw new Exception("Unable to load user information.");
                }
            }

            if (AppManager.UserLoaded())
            {
                // Refresh local information from the SSO server data.
                string Username = AppManager.GetField("username");
                string Firstname = AppManager.GetField("firstname");
                string Lastname = AppManager.GetField("lastname");

                // Save the data for later.
                AppManager.SetData("u", Username);
                AppManager.SetData("fn", Firstname);
                AppManager.SetData("ln", Lastname);
            }

            // Send the browser cookies.
            AppManager.SaveUserInfo();

//            // Test permissions for the user.
//            if (!AppManager.IsSiteAdmin() && !AppManager.HasTag("test_tag"))  AppManager.Login("", "insufficient_permissions", null);

            // Get the internal token for use with XSRF defenses.  Not used in this example.
            string UserToken = AppManager.GetSecretToken();
        }
	}
}
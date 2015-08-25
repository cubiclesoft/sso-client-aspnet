<%@ Page Language="C#" AutoEventWireup="true" CodeFile="Default.aspx.cs" Inherits="_Default" %>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
<title></title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
User ID:  <% Response.Write(SSO.Client.Manager.Instance.GetUserID()); %><br />
Username:  <% Response.Write(HttpUtility.HtmlEncode(SSO.Client.Manager.Instance.GetData("u"))); %><br />
First Name:  <% Response.Write(HttpUtility.HtmlEncode(SSO.Client.Manager.Instance.GetData("fn"))); %><br />
Last Name:  <% Response.Write(HttpUtility.HtmlEncode(SSO.Client.Manager.Instance.GetData("ln"))); %><br />
<br />
<a href="Default.aspx">Test local access</a><br />
<a href="Logout.aspx">Logout</a><br />
</body>
</html>

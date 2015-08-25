// Single Sign-On client manager for ASP.NET.
// (C) 2014 CubicleSoft.  All Rights Reserved.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Configuration;

namespace SSO.Client
{
    /// <summary>
    /// Very basic exception handler for the SSO client.
    /// </summary>
    public class SSOException : Exception
    {
        public SSOException()
        {
        }

        public SSOException(string message)
            : base(message)
        {
        }

        public SSOException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }

    /// <summary>
    /// IP address extraction and normalization class.  Direct PHP port for consistency.
    /// </summary>
    public class IPAddr
    {
        /// <summary>
        /// Normalizes an IP address into its IPv4 (if any), IPv6 long, and IPv6 short forms.
        /// </summary>
        public static NameValueCollection NormalizeIP(string IPAddr)
        {
            string IPv4 = "";
            string IPv6 = "";

            // Generate IPv6 address.
            IPAddr = IPAddr.Trim().ToLower();
            if (IPAddr.IndexOf(':') < 0)  IPAddr = "::ffff:" + IPAddr;
            string[] IPAddrArr = IPAddr.Split(':');
            if (IPAddrArr.Length < 3)  IPAddrArr = new string[] {"", "", "0"};
            List<string> IPAddr2 = new List<string>();
            int FoundPos = -1;
            for (int x = 0; x < IPAddrArr.Length; x++)
            {
                string Segment = IPAddrArr[x].Trim();
                if (Segment != "")  IPAddr2.Add(Segment);
                else if (FoundPos == -1 && IPAddrArr.Length > x + 1 && IPAddrArr[x + 1] != "")
                {
                    FoundPos = IPAddr2.Count;
                    IPAddr2.Add("0000");
                }
            }
            // Convert ::ffff:123.123.123.123 format.
            if (IPAddr2[IPAddr2.Count - 1].IndexOf('.') > -1)
            {
                int x = IPAddr2.Count - 1;
                if (IPAddr2[IPAddr2.Count - 2] != "ffff")  IPAddr2[x] = "0";
                else
                {
                    IPAddrArr = IPAddr2[x].Split('.');
                    if (IPAddrArr.Length != 4)  IPAddr2[x] = "0";
                    else
                    {
                        IPAddr2[x] = Convert.ToInt32(IPAddrArr[0]).ToString("x2") + Convert.ToInt32(IPAddrArr[1]).ToString("x2");
                        IPAddr2.Add(Convert.ToInt32(IPAddrArr[0]).ToString("x2") + Convert.ToInt32(IPAddrArr[1]).ToString("x2"));
                    }
                }
            }
            while (IPAddr2.Count > 8)  IPAddr2.RemoveAt(8);
            while (FoundPos > -1 && IPAddr2.Count < 8)
            {
                IPAddr2.Insert(FoundPos, "0000");
            }
            for (int x = 0; x < IPAddr2.Count; x++)
            {
                IPAddr2[x] = Convert.ToInt32(IPAddrArr[0], 16).ToString("x4").Substring(0, 4);
            }
            IPv6 = String.Join(":", IPAddr2.ToArray());

			// Extract IPv4 address.
            if (IPv6.Substring(0, 30) == "0000:0000:0000:0000:0000:ffff:")  IPv4 = Convert.ToInt32(IPv6.Substring(30, 2), 16).ToString() + "." + Convert.ToInt32(IPv6.Substring(32, 2), 16).ToString() + "." + Convert.ToInt32(IPv6.Substring(35, 2), 16).ToString() + "." + Convert.ToInt32(IPv6.Substring(37, 2), 16).ToString();

			// Make a short IPv6 address.
            string ShortIPv6 = IPv6;
            string Pattern = "0000:0000:0000:0000:0000:0000:0000";
            do
            {
                ShortIPv6 = ShortIPv6.Replace(Pattern, ":");
                Pattern = (Pattern.Length > 4 ? Pattern.Substring(5) : "");
            } while (ShortIPv6.Length == 39 && Pattern != "");
            string[] ShortIPv6Arr = ShortIPv6.Split(':');
            for (int x = 0; x < ShortIPv6Arr.Length; x++)
            {
                if (ShortIPv6Arr[x] != "")  ShortIPv6Arr[x] = ShortIPv6Arr[x].TrimStart('0');
            }
            ShortIPv6 = String.Join(":", ShortIPv6Arr);

            NameValueCollection Result = new NameValueCollection();
            Result["ipv6"] = IPv6;
            Result["shortipv6"] = ShortIPv6;
            Result["ipv4"] = IPv4;

            return Result;
        }

        /// <summary>
        /// Retrieves the normalized IP address of the current request.
        /// </summary>
        public static NameValueCollection GetRemoteIP(NameValueCollection Proxies)
        {
            NameValueCollection IPAddr = NormalizeIP(HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"] != null ? HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"] : "127.0.0.1");

			// Check for trusted proxies.  Stop at first untrusted IP in the chain.
            if (Proxies[IPAddr["ipv6"]] != null || (IPAddr["ipv4"] != "" && Proxies[IPAddr["ipv4"]] != null))
            {
                Stack<string> XForward = (HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"] != null ? new Stack<string>(HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"].Split(',')) : new Stack<string>());
                Stack<string> ClientIP = (HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"] != null ? new Stack<string>(HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"].Split(',')) : new Stack<string>());

                bool Found;
                do
                {
                    Found = false;

                    string Header;
                    if (Proxies[IPAddr["ipv6"]] != null)  Header = Proxies[IPAddr["ipv6"]];
                    else  Header = Proxies[IPAddr["ipv4"]];

                    Header = Header.ToLower();
                    if (Header == "xforward" && XForward.Count > 0)
                    {
                        IPAddr = NormalizeIP(XForward.Pop());
                        Found = true;
                    }
                    else if (Header == "clientip" && ClientIP.Count > 0)
                    {
                        IPAddr = NormalizeIP(ClientIP.Pop());
                        Found = true;
                    }
                } while (Found && (Proxies[IPAddr["ipv6"]] != null || (IPAddr["ipv4"] != "" && Proxies[IPAddr["ipv4"]] != null)));
            }

            return IPAddr;
        }
    }

    /// <summary>
    /// User information structure.  Used by Manager.
    /// </summary>
    public class UserInfoBase
    {
        public string sso_id;
        public string id;
        public string extra;
        public NameValueCollection field_map;
        public NameValueCollection writable;
        public NameValueCollection tag_map;
        public bool admin;
        public bool loaded;

        public UserInfoBase()
        {
            sso_id = "";
            id = "";
            extra = "";
            field_map = new NameValueCollection();
            writable = new NameValueCollection();
            tag_map = new NameValueCollection();
            admin = false;
            loaded = false;
        }
    }

    /// <summary>
    /// Cache information structure.  Used by Manager.
    /// </summary>
    public class UserCacheBase
    {
        public bool fromserver;
        public bool changed;
        public bool dbchanged;
        public bool hasdb;
        public string ts;
        public DateTime ts2;
        public string ipaddr;
        public NameValueCollection data;
        public NameValueCollection dbdata;

        public UserCacheBase()
        {
            fromserver = false;
            changed = false;
            dbchanged = false;
            hasdb = false;
            ts = "";
            ts2 = DateTime.MinValue;
            ipaddr = "";
            data = new NameValueCollection();
            dbdata = new NameValueCollection();
        }
    }

    /// <summary>
    /// Core management methods.
    /// </summary>
    public class Manager
    {
        private bool Initialized;
        private NameValueCollection Config;
        private NameValueCollection ManagerIPAddr;
        private RNGCryptoServiceProvider RNG;
        private bool CookieSent;
        private UserInfoBase UserInfo;
        private UserCacheBase UserCache;

        public NameValueCollection RequestVars;
        public NameValueCollection QueryString;
        public NameValueCollection Form;
        public NameValueCollection Cookies;

	    private Manager()
	    {
            Initialized = false;
            Config = new NameValueCollection((NameValueCollection)ConfigurationManager.GetSection("SSO.Client.SettingsGroup/SSO.Client.Settings"));
            ManagerIPAddr = null;
            RNG = new RNGCryptoServiceProvider();
            CookieSent = false;
            UserInfo = null;
            UserCache = null;

            // Initialize new read/write globals.
            QueryString = new NameValueCollection(HttpContext.Current.Request.QueryString);
            Form = new NameValueCollection(HttpContext.Current.Request.Form);
            Cookies = new NameValueCollection();
            foreach (string Key in HttpContext.Current.Request.Cookies)
            {
                Cookies[Key] = HttpContext.Current.Request.Cookies[Key].Value;
            }
            RequestVars = new NameValueCollection(Cookies);
            foreach (string Key in QueryString)
            {
                RequestVars[Key] = QueryString[Key];
            }
            foreach (string Key in Form)
            {
                RequestVars[Key] = Form[Key];
            }
	    }

        /// <summary>
        /// Retrieves a singleton instance of the SSO Client Manager.
        /// </summary>
        public static Manager Instance
        {
            get
            {
                if (HttpContext.Current.Items["sso_client_manager"] == null)  HttpContext.Current.Items["sso_client_manager"] = new Manager();

                return (Manager)HttpContext.Current.Items["sso_client_manager"];
            }
        }

        /// <summary>
        /// Checks to see if the SSO client is installed.
        /// </summary>
        public Boolean IsInstalled()
        {
            return (Config == null || Config.Count > 0);
        }

        /// <summary>
        /// Sets a configuration option.  Should only be used by the installer.
        /// </summary>
        public void SetConfigOption(string Key, string Val)
        {
            Config[Key] = Val;
        }

        /// <summary>
        /// Saves the configuration options.  Should only be used by the installer.
        /// </summary>
        public void SaveConfiguration()
        {
            Configuration WebConfig = WebConfigurationManager.OpenWebConfiguration("~");
            AppSettingsSection Section = (AppSettingsSection)WebConfig.GetSection("SSO.Client.SettingsGroup/SSO.Client.Settings");
            NameValueCollection Config2 = (NameValueCollection)ConfigurationManager.GetSection("SSO.Client.SettingsGroup/SSO.Client.Settings");
            foreach (string Key in Config)
            {
                Section.Settings.Add(Key, Config[Key]);
                Config2[Key] = Config[Key];
            }
            WebConfig.Save();
        }

        /// <summary>
        /// Returns the remote IP address based on configuration settings.
        /// </summary>
        public NameValueCollection GetRemoteIP()
        {
            NameValueCollection Proxies = new NameValueCollection();
            string[] IPAddrs = Config["proxy_x_forwarded_for"].Split(';');
            for (int x = 0; x < IPAddrs.Length; x++)
            {
                IPAddrs[x] = IPAddrs[x].Trim();
                if (IPAddrs[x] != "")  Proxies[IPAddrs[x]] = "xforward";
            }
            IPAddrs = Config["proxy_client_ip"].Split(';');
            for (int x = 0; x < IPAddrs.Length; x++)
            {
                IPAddrs[x] = IPAddrs[x].Trim();
                if (IPAddrs[x] != "")  Proxies[IPAddrs[x]] = "clientip";
            }

            return IPAddr.GetRemoteIP(Proxies);
        }

        /// <summary>
        /// Converts byte array to hex string.
        /// </summary>
        private string ConvertBytesToHex(byte[] Data)
        {
            StringBuilder Builder = new StringBuilder();

            for (int i = 0; i < Data.Length; i++)
            {
                Builder.Append(Data[i].ToString("x2"));
            }

            return Builder.ToString();
        }

        /// <summary>
        /// Converts hex string to byte array.
        /// </summary>
        private byte[] ConvertHexToBytes(String Data)
        {
            int Num = Data.Length / 2;
            byte[] Result = new byte[Num];
            using (StringReader sr = new StringReader(Data))
            {
                for (int i = 0; i < Num; i++)
                {
                    Result[i] = Convert.ToByte(new string(new char[2] {(char)sr.Read(), (char)sr.Read()}), 16);
                }
            }

            return Result;
        }

        /// <summary>
        /// Generates a token.
        /// </summary>
        public string GenerateToken(int Length)
        {
            byte[] Data = new byte[Length];

            RNG.GetBytes(Data);

            return ConvertBytesToHex(Data);
        }

        /// <summary>
        /// Packetizes and encrypts data with the specified key and options with AES.
        /// </summary>
        private byte[] AES_CreateDataPacket(byte[] Data, string Key, NameValueCollection Options)
        {
            Options = new NameValueCollection(Options);
            if (Options["prefix"] == null)  Options["prefix"] = GenerateToken(64);
            Options["prefix"] = DamienG.Security.Cryptography.Crc32.Compute(ConvertHexToBytes(Options["prefix"])).ToString("x");

            byte[] Hash;
            if (Options["lightweight"] == null || Options["lightweight"] == "false")  Hash = Encoding.UTF8.GetBytes(ConvertBytesToHex(SHA1.Create().ComputeHash(Data)));
            else  Hash = Encoding.UTF8.GetBytes(DamienG.Security.Cryptography.Crc32.Compute(Data).ToString("x"));
            
            // Packet:  Prefix + \n + Hash + \n + Data + \n + padding
            byte[] Prefix = Encoding.UTF8.GetBytes(Options["prefix"]);
            int PaddingStart = Prefix.Length + 1 + Hash.Length + 1 + Data.Length + 1;
            int PaddingEnd = PaddingStart + (PaddingStart % 16 == 0 ? 0 : 16 - (PaddingStart % 16));
            byte[] Data2 = new byte[PaddingEnd];
            System.Buffer.BlockCopy(Prefix, 0, Data2, 0, Prefix.Length);
            Data2[Prefix.Length] = (byte)'\n';
            System.Buffer.BlockCopy(Hash, 0, Data2, Prefix.Length + 1, Hash.Length);
            Data2[Prefix.Length + 1 + Hash.Length] = (byte)'\n';
            System.Buffer.BlockCopy(Data, 0, Data2, Prefix.Length + 1 + Hash.Length + 1, Data.Length);
            Data2[Prefix.Length + 1 + Hash.Length + 1 + Data.Length] = (byte)'\n';
            for (int x = PaddingStart; x < PaddingEnd; x++)  Data2[x] = (byte)'\0';

            // Set up to encrypt the packet.
            RijndaelManaged AES = new RijndaelManaged();
            if (Options["mode"] == null)  Options["mode"] = "ECB";
            if (Options["iv"] == null)  Options["iv"] = new String('0', 32);
            AES.Mode = (Options["mode"] == "CBC" ? CipherMode.CBC : CipherMode.ECB);
            AES.Key = ConvertHexToBytes(Key.Substring(0, 64));
            if (Options["iv"] != null)  AES.IV = ConvertHexToBytes(Options["iv"].Substring(0, 32));
            AES.Padding = PaddingMode.None;

            // Encrypt the packet.
            using (MemoryStream TempMemStream = new MemoryStream())
            {
                using (CryptoStream TempCryptoStream = new CryptoStream(TempMemStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    TempCryptoStream.Write(Data2, 0, Data2.Length);
                    Data = TempMemStream.ToArray();
                }
            }

            // Encrypt the data again if a second key is specified.
            if (Options["key2"] != null)
            {
                Data2 = new byte[Data.Length];
                Data2[0] = Data[Data.Length - 1];
                System.Buffer.BlockCopy(Data, 0, Data2, 1, Data.Length - 1);

                if (Options["iv2"] != null)  Options["iv"] = Options["iv2"];
                else  Options["iv"] = null;

                if (Options["mode"] != "ECB" && (Options["iv"] == null || Options["iv"] == ""))  throw new SSOException("No IV specified.");

                AES.Key = ConvertHexToBytes(Options["key2"].Substring(0, 64));
                if (Options["iv"] != null)  AES.IV = ConvertHexToBytes(Options["iv"].Substring(0, 32));
                AES.Padding = PaddingMode.None;

                // Encrypt the packet.
                using (MemoryStream TempMemStream = new MemoryStream())
                {
                    using (CryptoStream TempCryptoStream = new CryptoStream(TempMemStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        TempCryptoStream.Write(Data2, 0, Data2.Length);
                        Data = TempMemStream.ToArray();
                    }
                }
            }

            return Data;
        }

        /// <summary>
        /// Uses AES to extract the data from an encapsulated data packet and validates the data.
        /// </summary>
        private byte[] AES_ExtractDataPacket(byte[] Data, string Key, NameValueCollection Options)
        {
            Options = new NameValueCollection(Options);
            if (Options["mode"] == null)  Options["mode"] = "ECB";
            if (Options["mode"] != "ECB" && (Options["iv"] == null || Options["iv"] == ""))  throw new SSOException("No IV specified.");

            byte[] Data2;
            RijndaelManaged AES = new RijndaelManaged();
            if (Options["key2"] != null)
            {
                AES.Mode = (Options["mode"] == "CBC" ? CipherMode.CBC : CipherMode.ECB);
                AES.Key = ConvertHexToBytes(Options["key2"].Substring(0, 64));
                if (Options["iv2"] != null)  AES.IV = ConvertHexToBytes(Options["iv2"].Substring(0, 32));
                AES.Padding = PaddingMode.None;

                // Decrypt the packet.
                using (MemoryStream TempMemStream = new MemoryStream(Data))
                {
                    using (CryptoStream TempCryptoStream = new CryptoStream(TempMemStream, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        Data2 = new byte[Data.Length];
                        TempCryptoStream.Read(Data2, 0, Data2.Length);
                    }
                }

                Data = new byte[Data2.Length];
                System.Buffer.BlockCopy(Data2, 1, Data, 0, Data2.Length - 1);
                Data[Data2.Length - 1] = Data2[0];
            }

            AES.Mode = (Options["mode"] == "CBC" ? CipherMode.CBC : CipherMode.ECB);
            AES.Key = ConvertHexToBytes(Key.Substring(0, 64));
            if (Options["iv"] != null)  AES.IV = ConvertHexToBytes(Options["iv"].Substring(0, 32));
            AES.Padding = PaddingMode.None;

            // Decrypt the packet.
            using (MemoryStream TempMemStream = new MemoryStream(Data))
            {
                using (CryptoStream TempCryptoStream = new CryptoStream(TempMemStream, AES.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    Data2 = new byte[Data.Length];
                    TempCryptoStream.Read(Data2, 0, Data2.Length);
                }
            }

            // Ignore the first chunk.
            int Pos = Array.IndexOf(Data2, (byte)'\n');
            if (Pos < 0 || Pos == Data2.Length - 1)  throw new SSOException("Invalid packet.");
            Data = new byte[Data2.Length - Pos - 1];
            System.Buffer.BlockCopy(Data2, Pos + 1, Data, 0, Data2.Length - Pos - 1);

            // Extract the hash check.
            Pos = Array.IndexOf(Data, (byte)'\n');
            if (Pos < 0 || Pos == Data.Length - 1)  throw new SSOException("Invalid packet.");
            byte[] Data3 = new byte[Pos];
            System.Buffer.BlockCopy(Data, 0, Data3, 0, Pos);
            string Check = Encoding.UTF8.GetString(Data3);
            Data2 = new byte[Data.Length - Pos - 1];
            System.Buffer.BlockCopy(Data, Pos + 1, Data2, 0, Data.Length - Pos - 1);

            // Extract the data.
            Pos = Array.LastIndexOf(Data2, (byte)'\n');
            if (Pos < 0)  throw new SSOException("Invalid packet.");
            Data = new byte[Pos];
            System.Buffer.BlockCopy(Data2, 0, Data, 0, Pos);

            // Check the hash.
            if (Options["lightweight"] == null || Options["lightweight"] == "false")
            {
                if (ConvertBytesToHex(SHA1.Create().ComputeHash(Data)) != Check)  throw new SSOException("Invalid packet.");
            }
            else
            {
                if (DamienG.Security.Cryptography.Crc32.Compute(Data).ToString("x") != Check)  throw new SSOException("Invalid packet.");
            }

            return Data;
        }

        private static byte[] Base64Decode(string Text)
        {
            while (Text.Length % 4 != 0)  Text += '=';

            var TextBytes = Convert.FromBase64String(Text);

            return Convert.FromBase64String(Text);
        }

        private static long CopyTo(Stream Source, Stream Dest)
        {
            byte[] Data = new byte[2048];
            int NumRead;
            long Total = 0;

            while ((NumRead = Source.Read(Data, 0, Data.Length)) > 0)
            {
                Dest.Write(Data, 0, NumRead);
                Total += NumRead;
            }

            return Total;
        }

        private static byte[] Compress(byte[] Data)
        {
            using (MemoryStream MemStreamInput = new MemoryStream(Data))
            {
                using (MemoryStream MemStreamOutput = new MemoryStream())
                {
                    using (GZipStream TempGZipStream = new GZipStream(MemStreamOutput, CompressionMode.Compress))
                    {
                        CopyTo(MemStreamInput, TempGZipStream);
                    }

                    return MemStreamOutput.ToArray();
                }
            }
        }

        private static byte [] Uncompress(byte[] bytes)
        {
            using (MemoryStream MemStreamInput = new MemoryStream(bytes))
            {
                using (MemoryStream MemStreamOutput = new MemoryStream())
                {
                    using (GZipStream TempGZipStream = new GZipStream(MemStreamInput, CompressionMode.Decompress))
                    {
                        CopyTo(TempGZipStream, MemStreamOutput);
                    }

                    return MemStreamOutput.ToArray();
                }
            }
        }

        private static DateTime UTCToLocalDate(string Date)
        {
            Regex TempReg = new Regex("[^0-9]");
            Date = TempReg.Replace(Date, " ");
            string[] Items = Date.Trim().Split(' ');
            DateTime TempDateTime = new DateTime(Convert.ToInt32(Items[0]), Convert.ToInt32(Items[1]), Convert.ToInt32(Items[2]), Convert.ToInt32(Items[3]), Convert.ToInt32(Items[4]), Convert.ToInt32(Items[5]), DateTimeKind.Utc);
            TempDateTime = TempDateTime.ToLocalTime();

            return TempDateTime;
        }

        /// <summary>
        /// Prepares and sends a packet to a server and returns the response.
        /// </summary>
        public JObject SendRequest(string Action, NameValueCollection Options)
        {
            return SendRequest(Action, Options, null, null, null);
        }

        /// <summary>
        /// Prepares and sends a packet to a server and returns the response.
        /// </summary>
        public JObject SendRequest(string Action, NameValueCollection Options, string Endpoint, string APIKey, string SecretKey)
        {
            if (Options == null)  Options = new NameValueCollection();
            if (Endpoint == null)  Endpoint = Config["server_endpoint_url"];
            if (APIKey == null)  APIKey = Config["server_apikey"];
            if (SecretKey == null)  SecretKey = Config["server_secretkey"];

            if (ManagerIPAddr == null)  ManagerIPAddr = GetRemoteIP();

            string URL = Endpoint;
            URL += (Endpoint.IndexOf('?') > -1 ? "&" : "?");
            URL += "apikey=" + HttpUtility.UrlEncode(APIKey);
            URL += "&action=" + HttpUtility.UrlEncode(Action);
            URL += "&ipaddr=" + HttpUtility.UrlEncode(ManagerIPAddr["ipv6"]);
            URL += "&ver=3.0";

            HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(URL);
            Request.ReadWriteTimeout = 10000;
            Request.Timeout = 10000;
            Request.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0";
            Request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            Request.Headers.Add("Accept-Language", "en-us,en;q=0.5");
            Request.Headers.Add("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7");
            Request.Headers.Add("Cache-Control", "max-age=0");
            Request.Method = "POST";
            Request.ContentType = "application/x-www-form-urlencoded";

            // Create encrypted data packet.
            Options["apikey"] = APIKey;
            Options["action"] = Action;
            Options["ver"] = "3.0";
            Options["ts"] = DateTime.Now.ToUniversalTime().ToString("u").Replace("Z", "");
            JObject TempObj = new JObject();
            foreach (string Key in Options)
            {
                TempObj[Key] = Options[Key];
            }
            string Data = JsonConvert.SerializeObject(TempObj);
            NameValueCollection CryptOpts = new NameValueCollection();
            CryptOpts["mode"] = "CBC";
            string Mode = "unknown", CryptKey;
            if (SecretKey.IndexOf(':') < 0)  throw new SSOException("Old secret keys are not supported in ASP.NET.  Generate a new secret key.");
            else
            {
                string[] Info = SecretKey.Split(':');
                if (Info.Length < 3)  throw new SSOException("Invalid secret key.");

                Mode = Info[0];
                CryptKey = Info[1];
                CryptOpts["iv"] = Info[2];

                if (Info.Length >= 5)
                {
                    CryptOpts["key2"] = Info[3];
                    CryptOpts["iv2"] = Info[4];
                }
            }

            byte[] Data2;
            if (Mode == "aes256")  Data2 = AES_CreateDataPacket(Encoding.UTF8.GetBytes(Data), CryptKey, CryptOpts);
            else  throw new SSOException("Unknown mode '" + Mode + "'.  Only 'aes256' is supported.");

            Data = Convert.ToBase64String(Data2);
            Data2 = Encoding.UTF8.GetBytes("data=" + HttpUtility.UrlEncode(Data.Replace('+', '-').Replace('/', '_').Replace("=", "")));

            Stream DataStream = Request.GetRequestStream();
            DataStream.Write(Data2, 0, Data2.Length);
            DataStream.Close();

            // Send the request and get the response.
            // Don't retry failures under ASP.NET.
            JObject Result;
            try
            {
                HttpWebResponse Response = (HttpWebResponse)Request.GetResponse();
                DataStream = Response.GetResponseStream();
                StreamReader Reader = new StreamReader(DataStream);
                Data = Reader.ReadToEnd();
                Reader.Close();
                DataStream.Close();
                Response.Close();
            }
            catch (Exception e)
            {
                Result = new JObject();
                Result["success"] = false;
                Result["error"] = "An error occurred while processing the request.";
                Result["info"] = e.Message;

                return Result;
            }

			// Decode and extract response.
            if (Data.Length == 0)  throw new SSOException("Empty response returned from server.");
            else if (Data[0] == '{')  Result = JsonConvert.DeserializeObject<JObject>(Data.Trim());
            else
            {
                Data2 = Base64Decode(Data.Trim());

                if (Mode == "aes256")  Data2 = AES_ExtractDataPacket(Data2, CryptKey, CryptOpts);
                else  throw new SSOException("Unknown mode '" + Mode + "'.  Only 'aes256' is supported.");

                Result = JsonConvert.DeserializeObject<JObject>(Encoding.UTF8.GetString(Data2));
            }

            return Result;
        }

        public void SetCookieFixDomain(string Name, string Value, DateTime Expires, string Path, string Domain, bool Secure, bool HTTPOnly)
        {
            if (Value == null)  Value = "";
            if (Path == null)  Path = "";
            if (Domain == null)  Domain = "";

            if (Domain != "")
            {
				// Fix the domain to accept domains with and without 'www.'.
                if (Domain.Length > 4 && Domain.Substring(0, 4).ToLower() == "www.")  Domain = Domain.Substring(4);
                if (Domain.IndexOf('.') < 0)  Domain = "";
                else  Domain = "." + Domain;

				// Remove port information.
                if (Domain.IndexOf(':') > -1)  Domain = Domain.Substring(0, Domain.IndexOf(':'));
            }

            HttpCookie TempCookie = new HttpCookie(Name, Value);
            if (Expires != DateTime.MinValue)  TempCookie.Expires = Expires;
            if (Path != "")  TempCookie.Path = Path;
            if (Domain != "")  TempCookie.Domain = Domain;
            TempCookie.Secure = Secure;
            TempCookie.HttpOnly = HTTPOnly;

            HttpContext.Current.Response.SetCookie(TempCookie);

            Cookies[Name] = Value;
            RequestVars[Name] = Value;
            QueryString.Remove(Name);
            Form.Remove(Name);

            if (!CookieSent)
            {
                HttpContext.Current.Response.Cache.SetExpires(DateTime.UtcNow.AddDays(-1));
                HttpContext.Current.Response.Cache.SetCacheability(HttpCacheability.NoCache);
                HttpContext.Current.Response.Cache.SetNoStore();
                HttpContext.Current.Response.Headers.Add("Pragma", "no-cache");
                HttpContext.Current.Response.Expires = -1;

                CookieSent = true;
            }
        }

        public bool IsSSLRequest()
        {
            return HttpContext.Current.Request.IsSecureConnection;
        }

		public string GetRequestHost(string Protocol)
		{
            if (Protocol == null)  Protocol = "";

			Protocol = Protocol.ToLower();
			bool SSL = (Protocol == "https" || (Protocol == "" && IsSSLRequest()));

            string Result = (SSL ? "https://" : "http://");
            Result += HttpContext.Current.Request.Url.Host.ToLower();
            int Port = HttpContext.Current.Request.Url.Port;
            if (Port < 1 || Port > 65536)  Port = (SSL ? 443 : 80);
            if (Protocol == "" && ((!SSL && Port != 80) || (SSL && Port != 443)))  Result += ":" + Port;
            else if (Protocol == "http" && !SSL && Port != 80)  Result += ":" + Port;
            else if (Protocol == "https" && SSL && Port != 443)  Result += ":" + Port;

            return Result;
        }

        public string GetRequestURLBase()
        {
            return HttpContext.Current.Request.Url.LocalPath;
        }

		public string GetFullRequestURLBase(string Protocol)
		{
			return GetRequestHost(Protocol) + GetRequestURLBase();
		}


        private void ProcessLogin(JObject Info, bool FromServer)
        {
            UserInfo = new UserInfoBase();
            UserInfo.sso_id = (string)Info["sso_id"];
            UserInfo.id = (string)Info["id"];
            UserInfo.extra = (string)Info["extra"];
            if (Info["field_map"].Type == JTokenType.Object)
            {
                JObject TempMap = (JObject)Info["field_map"];
                foreach (var x in TempMap)  UserInfo.field_map[x.Key] = (string)x.Value;
            }
            if (Info["writable"].Type == JTokenType.Object)
            {
                JObject TempMap = (JObject)Info["writable"];
                foreach (var x in TempMap)  UserInfo.writable[x.Key] = "1";
            }
            if (Info["tag_map"].Type == JTokenType.Object)
            {
                JObject TempMap = (JObject)Info["tag_map"];
                foreach (var x in TempMap)  UserInfo.tag_map[x.Key] = "1";
            }
            UserInfo.admin = (bool)Info["admin"];
            UserInfo.loaded = true;

            UserCache = new UserCacheBase();
            UserCache.fromserver = FromServer;
            UserCache.changed = true;
            UserCache.dbchanged = true;
            UserCache.hasdb = false;
            UserCache.ts = DateTime.Now.AddSeconds(Convert.ToInt32(Config["cookie_check"])).ToUniversalTime().ToString("u").Replace("Z", "");
            UserCache.ts2 = DateTime.Now.AddSeconds(Convert.ToInt32(Config["cookie_check"]));
            UserCache.ipaddr = (ManagerIPAddr["ipv4"] != "" && ManagerIPAddr["ipv4"].Length < ManagerIPAddr["shortipv6"].Length ? ManagerIPAddr["ipv4"] : ManagerIPAddr["shortipv6"]);

            Cookies.Remove(Config["cookie_name"] + "_c");
            Cookies.Remove(Config["cookie_name"] + "_s");
            Cookies.Remove(Config["cookie_name"] + "_v");

            if (Info["rinfo"] != null)
            {
                try
                {
                    byte[] Data = Base64Decode((string)Info["rinfo"]);
                    NameValueCollection Options = new NameValueCollection();
                    Options["mode"] = "CBC";
                    Options["iv"] = Config["rand_seed8"];
                    Options["key2"] = Config["rand_seed9"];
                    Options["iv2"] = Config["rand_seed10"];
                    Data = AES_ExtractDataPacket(Data, Config["rand_seed7"], Options);
                    Data = Uncompress(Data);
                    JObject TempMap = JsonConvert.DeserializeObject<JObject>(Encoding.UTF8.GetString(Data));

                    // Reload.
                    QueryString = new NameValueCollection();
                    foreach (var x in (JObject)TempMap["get"])  QueryString[x.Key] = (string)x.Value;
                    Form = new NameValueCollection();
                    foreach (var x in (JObject)TempMap["post"])  Form[x.Key] = (string)x.Value;
                    RequestVars = new NameValueCollection();
                    foreach (var x in (JObject)TempMap["request"])  RequestVars[x.Key] = (string)x.Value;
                }
                catch (Exception)
                {
                }
            }

			// Reinitialize stored input.
            QueryString.Remove(Config["cookie_name"] + "_c");
            QueryString.Remove(Config["cookie_name"] + "_s");
            QueryString.Remove(Config["cookie_name"] + "_v");
            Form.Remove(Config["cookie_name"] + "_c");
            Form.Remove(Config["cookie_name"] + "_s");
            Form.Remove(Config["cookie_name"] + "_v");
        }

        /// <summary>
        /// Perform redirection to current URL minus specified parameters.
        /// </summary>
        private void SafeRedirect(string[] RemoveKeys)
        {
            string URL = GetFullRequestURLBase(null);

            for (int x = 0; x < RemoveKeys.Length; x++)
            {
                QueryString.Remove(RemoveKeys[x]);
            }
            if (QueryString.Count > 0)
            {
                string TempStr = "";
                foreach (string Key in QueryString)
                {
                    if (TempStr != "")  TempStr += "&";
                    TempStr += HttpUtility.UrlEncode(Key) + "=" + HttpUtility.UrlEncode(QueryString[Key]);
                }
                URL += "?" + TempStr;
            }

            HttpContext.Current.Response.Redirect(URL);
        }

        public bool LoggedIn()
        {
            if (UserInfo != null)  return (UserInfo.sso_id != "");
            if (RequestVars[Config["cookie_name"] + "_s"] == null)  return false;

            try
            {
                // Decrypt the cookie.
                UserInfo = new UserInfoBase();
                byte[] CData = Base64Decode(RequestVars[Config["cookie_name"] + "_s"].Replace('-', '+').Replace('_', '/'));

                NameValueCollection Options = new NameValueCollection();
                Options["mode"] = "CBC";
                Options["iv"] = Config["rand_seed2"];
                Options["key2"] = Config["rand_seed4"];
                Options["iv2"] = Config["rand_seed5"];
                Options["lightweight"] = "true";
                CData = AES_ExtractDataPacket(CData, Config["rand_seed"], Options);

                if (CData.Length > 2)
                {
                    byte[] APIKey = Encoding.UTF8.GetBytes(Config["server_apikey"]);
                    byte[] CData2 = new byte[CData.Length + 1 + APIKey.Length];
                    System.Buffer.BlockCopy(CData, 0, CData2, 0, CData.Length);
                    CData2[CData.Length] = (byte)':';
                    System.Buffer.BlockCopy(APIKey, 0, CData2, CData.Length + 1, APIKey.Length);
                    string VData;
                    using (HMACSHA1 TempHMAC = new HMACSHA1(ConvertHexToBytes(Config["rand_seed6"])))
                    {
                        TempHMAC.ComputeHash(CData2);
                        VData = Convert.ToBase64String(TempHMAC.Hash);
                    }

                    bool Compressed = (CData[0] == (byte)'1');
                    CData2 = new byte[CData.Length - 2];
                    System.Buffer.BlockCopy(CData, 2, CData2, 0, CData.Length - 2);
                    CData = (Compressed ? Uncompress(CData2) : CData2);
                    JObject CDataObj = JsonConvert.DeserializeObject<JObject>(Encoding.UTF8.GetString(CData));

                    // Load the user information structure.
                    UserInfo.sso_id = (string)CDataObj["s"];
                    UserInfo.id = (string)CDataObj["i"];
                    UserInfo.extra = (string)CDataObj["e"];
                    if (CDataObj["t"] != null)
                    {
                        foreach (var x in (JObject)CDataObj["t"])  UserInfo.tag_map[x.Key] = "1";
                    }
                    if (CDataObj["a"] != null)  UserInfo.admin = ((int)CDataObj["a"] == 1);

                    UserCache = new UserCacheBase();
                    if (CDataObj["b"] != null)  UserCache.hasdb = ((int)CDataObj["b"] == 1);
                    UserCache.ts = (string)CDataObj["c"];
                    UserCache.ipaddr = (ManagerIPAddr["ipv4"] != "" && ManagerIPAddr["ipv4"].Length < ManagerIPAddr["shortipv6"].Length ? ManagerIPAddr["ipv4"] : ManagerIPAddr["shortipv6"]);
                    if (CDataObj["d"] != null)
                    {
                        foreach (var x in (JObject)CDataObj["d"])  UserCache.data[x.Key] = (string)x.Value;
                    }

                    // If the verification cookie is missing or invalid, logout of the session.
                    if (RequestVars[Config["cookie_name"] + "_v"] == null || RequestVars[Config["cookie_name"] + "_v"].Replace('-', '+').Replace('_', '/') != VData.Replace("=", ""))
                    {
                        Logout();

                        return false;
                    }

                    // Check for outdated login information.
                    UserCache.ts2 = UTCToLocalDate(UserCache.ts);
                    if (RequestVars[Config["cookie_name"] + "_c"] == null || UserCache.ts2 < DateTime.Now || UserCache.ipaddr != (string)CDataObj["p"] || (IsSiteAdmin() && Config["client_check_site_admin"] == "1"))
                    {
                        // Reset the session if the IP address changed.
                        if (Config["cookie_reset_ipaddr_changes"] == "1" && UserCache.ipaddr != (string)CDataObj["p"])
                        {
                            UserInfo.sso_id = "";

                            return false;
                        }

                        // Validate the login.  Handle scenarios where the SSO Server is unavailable.
                        Options = new NameValueCollection();
                        Options["sso_id"] = UserInfo.sso_id;
                        Options["expires"] = (Convert.ToInt32(Config["cookie_timeout"]) > 0 && Convert.ToInt32(Config["cookie_timeout"]) < Convert.ToInt32(Config["server_session_timeout"]) ? Config["cookie_timeout"] : Config["server_session_timeout"]);

                        JObject Result = SendRequest("getlogin", Options);
                        if (!(bool)Result["success"] && Result["info"] == null)
                        {
                            UserInfo.sso_id = "";

                            return false;
                        }
                        if ((bool)Result["success"])  ProcessLogin(Result, false);
                    }

                    return true;
                }
            }
            catch (Exception)
            {
            }

            return false;
        }

		public bool FromSSOServer()
		{
			return UserCache.fromserver;
		}

        /// <summary>
        /// Self-contained initialization.  Must be called before everything else in a client application.
        /// </summary>
        public void Init(string[] RemoveKeys)
        {
            if (Initialized)  return;

			// Initialize IP address for API calls.
            ManagerIPAddr = GetRemoteIP();

			// Redirect the browser to a similar URL.
            if (RequestVars["from_sso_server"] != null && RequestVars["sso_id"] != null && RequestVars["sso_id2"] != null)
            {
                SetCookieFixDomain(Config["cookie_name"] + "_s_id", RequestVars["sso_id"], DateTime.MinValue, Config["cookie_path"], "", IsSSLRequest(), true);
                SetCookieFixDomain(Config["cookie_name"] + "_s_id2", RequestVars["sso_id2"], DateTime.MinValue, Config["cookie_path"], "", IsSSLRequest(), true);

                SafeRedirect(new string[] { "sso_id", "sso_id2" });
            }

			// If the input request appears to be from the SSO server and a new session, process the new session.
            if (RequestVars["from_sso_server"] != null && Cookies[Config["cookie_name"] + "_s_id"] != null && Cookies[Config["cookie_name"] + "_s_id2"] != null)
            {
				// Validate the login and get the original request data back.
                NameValueCollection Options = new NameValueCollection();
                Options["sso_id"] = Cookies[Config["cookie_name"] + "_s_id"];
                Options["sso_id2"] = Cookies[Config["cookie_name"] + "_s_id2"];
                Options["rid"] = (Cookies[Config["cookie_name"] + "_rid"] != null ? Cookies[Config["cookie_name"] + "_rid"] : "");
                Options["expires"] = (Convert.ToInt32(Config["cookie_timeout"]) > 0 && Convert.ToInt32(Config["cookie_timeout"]) < Convert.ToInt32(Config["server_session_timeout"]) ? Config["cookie_timeout"] : Config["server_session_timeout"]);

                JObject Result = SendRequest("getlogin", Options);
                if ((bool)Result["success"])
                {
					// Process the login.
                    ProcessLogin(Result, true);

					// Delete the old session.
                    Options["delete_old"] = "1";
                    SendRequest("getlogin", Options);

					// Delete ID cookies.
                    SetCookieFixDomain(Config["cookie_name"] + "_s_id", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", IsSSLRequest(), true);
                    SetCookieFixDomain(Config["cookie_name"] + "_s_id2", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", IsSSLRequest(), true);

					// Delete the recovery cookie.
                    SetCookieFixDomain(Config["cookie_name"] + "_rid", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", IsSSLRequest(), true);
                }
            }

            if (RequestVars["from_sso_server"] != null && RequestVars["sso_setlogin_id"] != null && RequestVars["sso_setlogin_token"] != null)
            {
                SetCookieFixDomain(Config["cookie_name"] + "_sr_id", RequestVars["sso_setlogin_id"], DateTime.MinValue, Config["cookie_path"], "", IsSSLRequest(), true);
                SetCookieFixDomain(Config["cookie_name"] + "_sr_t", RequestVars["sso_setlogin_token"], DateTime.MinValue, Config["cookie_path"], "", IsSSLRequest(), true);

                SafeRedirect(new string[] { "sso_setlogin_id", "sso_setlogin_token" });
            }

            if (LoggedIn() && !FromSSOServer() && RemoveKeys != null)
            {
                for (int x = 0; x < RemoveKeys.Length; x++)
                {
                    if (QueryString[RemoveKeys[x]] != null)  SafeRedirect(RemoveKeys);
                }
            }

            QueryString.Remove("from_sso_server");
            Form.Remove("from_sso_server");
            RequestVars.Remove("from_sso_server");

            Initialized = true;
        }

        public void Login(string Lang, string Message, NameValueCollection Extra)
        {
            if (Lang == null)  Lang = "";
            if (Message == null)  Message = "";
            if (Extra == null)  Extra = new NameValueCollection();

            if (Message != "" || !LoggedIn())
            {
                // Send current context, retrieve the login location from the SSO server, and redirect the user.
                string URL = GetFullRequestURLBase(null) + HttpContext.Current.Request.Url.Query;

                JObject Vars = new JObject();

                JObject TempGetVars = new JObject();
                foreach (string Key in QueryString)  TempGetVars[Key] = QueryString[Key];
                Vars["get"] = TempGetVars;

                JObject TempPostVars = new JObject();
                foreach (string Key in Form)  TempPostVars[Key] = Form[Key];
                Vars["post"] = TempPostVars;

                JObject TempRequestVars = new JObject();
                foreach (string Key in RequestVars)  TempRequestVars[Key] = RequestVars[Key];
                Vars["request"] = TempRequestVars;

                string Data = JsonConvert.SerializeObject(Vars);
                NameValueCollection Options = new NameValueCollection();
                Options["mode"] = "CBC";
                Options["iv"] = Config["rand_seed8"];
                Options["key2"] = Config["rand_seed9"];
                Options["iv2"] = Config["rand_seed10"];
                Data = Convert.ToBase64String(AES_CreateDataPacket(Compress(Encoding.UTF8.GetBytes(Data)), Config["rand_seed7"], Options));

                Options = new NameValueCollection();
                Options["url"] = URL;
                Options["info"] = Data;
                Options["files"] = (HttpContext.Current.Request.Files.Count > 0 ? "1" : "0");
                Options["lang"] = Lang;
                Options["initmsg"] = Message;

                JObject Result = SendRequest("initlogin", Options);
                if (!(bool)Result["success"])  throw new SSOException("Unable to obtain SSO server login access.  Error:  " + (string)Result["error"]);

                // Set the recovery ID to be able to retrieve the old data later.  Doubles as a XSRF defense.
                SetCookieFixDomain(Config["cookie_name"] + "_rid", (string)Result["rid"], DateTime.MinValue, Config["cookie_path"], "", IsSSLRequest(), true);

                URL = (string)Result["url"];
                foreach (string Key in Extra)  URL += "&" + HttpUtility.UrlEncode(Key) + "=" + HttpUtility.UrlEncode(Extra[Key]);

                HttpContext.Current.Response.Redirect(URL);
            }
        }

        public bool CanRemoteLogin()
        {
            return (RequestVars[Config["cookie_name"] + "_sr_id"] != null && RequestVars[Config["cookie_name"] + "_sr_t"] != null);
        }

        public void RemoteLogin(string UserID, NameValueCollection FieldMap)
        {
            RemoteLogin(UserID, FieldMap, null, null, null);
        }

        public void RemoteLogin(string UserID, NameValueCollection FieldMap, string Endpoint, string APIKey, string SecretKey)
        {
            if (FieldMap == null)  FieldMap = new NameValueCollection();

            if (!CanRemoteLogin())  throw new SSOException("Unable to retrieve ID or token cookie for SSO server login.");

            NameValueCollection Options = new NameValueCollection();
            Options["sso_id"] = RequestVars[Config["cookie_name"] + "_sr_id"];
            Options["token"] = RequestVars[Config["cookie_name"] + "_sr_t"];
            Options["user_id"] = UserID;

            JObject Vars = new JObject();
            foreach (string Key in FieldMap)  Vars[Key] = FieldMap[Key];
            Options["updateinfo"] = JsonConvert.SerializeObject(Vars);

            JObject Result = SendRequest("setlogin", Options, Endpoint, APIKey, SecretKey);
            if (!(bool)Result["success"])  throw new SSOException("Unable to obtain SSO server remote login access.  Error:  " + (string)Result["error"]);

            // Delete the cookies.
            SetCookieFixDomain(Config["cookie_name"] + "_sr_id", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", IsSSLRequest(), true);
            SetCookieFixDomain(Config["cookie_name"] + "_sr_t", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", IsSSLRequest(), true);

            HttpContext.Current.Response.Redirect((string)Result["url"]);
        }

        public void Logout()
        {
            if (UserInfo != null && UserInfo.sso_id != "")
            {
                NameValueCollection Options = new NameValueCollection();
                Options["sso_id"] = UserInfo.sso_id;

                SendRequest("logout", Options);

                UserInfo.sso_id = "";
            }

            SetCookieFixDomain(Config["cookie_name"] + "_c", "0", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), true);
            SetCookieFixDomain(Config["cookie_name"] + "_s", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), true);
            SetCookieFixDomain(Config["cookie_name"] + "_v", "", DateTime.MinValue.AddDays(1), Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), true);
        }

        public bool HasDBData()
        {
            return UserCache.hasdb;
        }

        public bool LoadDBData(string Data)
        {
            try
            {
                NameValueCollection Options = new NameValueCollection();
                Options["mode"] = "CBC";
                string[] Data2 = Data.Split(':');
                if (Data2.Length != 3)  return false;
                if (Data2[0] != "aes256")  return false;
                Options["iv"] = Config["rand_seed12"];
                if (Convert.ToInt32(Data2[1]) == 2)
                {
                    Options["key2"] = Config["rand_seed13"];
                    Options["iv2"] = Config["rand_seed14"];
                }
                Data = Data2[2];

                byte[] Data3 = AES_ExtractDataPacket(Convert.FromBase64String(Data), Config["rand_seed11"], Options);
                bool Compressed = (Data3[0] == (byte)'1');
                byte[] Data4 = new byte[Data3.Length - 2];
                System.Buffer.BlockCopy(Data3, 2, Data4, 0, Data3.Length - 2);
                Data3 = (Compressed ? Uncompress(Data4) : Data4);
                JObject DataObj = JsonConvert.DeserializeObject<JObject>(Encoding.UTF8.GetString(Data3));

                UserCache.dbdata = new NameValueCollection();
                foreach (var x in DataObj)  UserCache.dbdata[x.Key] = (string)x.Value;

                return true;
            }
            catch (Exception)
            {
            }

            return false;
        }

        public string SaveDBData()
        {
            JObject DBData = new JObject();
            foreach (string Key in UserCache.dbdata)  DBData[Key] = UserCache.dbdata[Key];
            byte[] Data2 = Compress(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(DBData)));
            byte[] Data = new byte[Data2.Length + 2];
            Data[0] = (byte)'1';
            Data[1] = (byte)':';
            System.Buffer.BlockCopy(Data2, 0, Data, 2, Data2.Length);

            NameValueCollection Options = new NameValueCollection();
            Options["mode"] = "CBC";
            Options["iv"] = Config["rand_seed12"];
            Options["key2"] = Config["rand_seed13"];
            Options["iv2"] = Config["rand_seed14"];

            string Result = "aes256:2:" + Convert.ToBase64String(AES_CreateDataPacket(Data, Config["rand_seed11"], Options));

            return Result;
        }

        public bool IsSiteAdmin()
        {
            return (Config["client_accept_site_admin"] == "1" ? UserInfo.admin : false);
        }

        public bool HasTag(string Name)
        {
            return (UserInfo.tag_map[Name] != null);
        }

        public bool LoadUserInfo()
        {
            return LoadUserInfo(false);
        }

        public bool LoadUserInfo(bool SaveFirst)
        {
            if (UserInfo == null)  return false;
            if (!SaveFirst && UserInfo.loaded)  return true;

            NameValueCollection Options = new NameValueCollection();
            Options["sso_id"] = UserInfo.sso_id;
            Options["expires"] = (Convert.ToInt32(Config["cookie_timeout"]) > 0 && Convert.ToInt32(Config["cookie_timeout"]) < Convert.ToInt32(Config["server_session_timeout"]) ? Config["cookie_timeout"] : Config["server_session_timeout"]);
            if (SaveFirst)
            {
                JObject Vars = new JObject();
                foreach (string Key in UserInfo.field_map)  Vars[Key] = UserInfo.field_map[Key];
                Options["updateinfo"] = JsonConvert.SerializeObject(Vars);
            }

            JObject Result = SendRequest("getlogin", Options);
            if (!(bool)Result["success"] && Result["info"] == null)  return false;
            if ((bool)Result["success"])  ProcessLogin(Result, false);

            return UserInfo.loaded;
        }

        public bool UserLoaded()
        {
            return UserInfo.loaded;
        }

        public string GetField(string Key)
        {
            return GetField(Key, null);
        }

        public string GetField(string Key, string Default)
        {
            return (UserInfo.field_map[Key] != null ? UserInfo.field_map[Key] : Default);
        }

        public NameValueCollection GetEditableFields()
        {
            return new NameValueCollection(UserInfo.writable);
        }

        public bool SetField(string Key, string Value)
        {
            if (UserInfo.writable[Key] == null)  return false;
            UserInfo.writable[Key] = Value;

            return true;
        }

        public string GetData(string Key)
        {
            return GetData(Key, null);
        }

        public string GetData(string Key, string Default)
        {
            if (UserCache.data[Key] != null)  return UserCache.data[Key];
            if (UserCache.dbdata[Key] != null)  return UserCache.dbdata[Key];

            return Default;
        }

        public bool SetData(string Key, string Value)
        {
            return SetData(Key, Value, 50);
        }

        public bool SetData(string Key, string Value, int MaxCookieLen)
        {
            if (UserCache.data[Key] != null && UserCache.data[Key] == Value)  return false;
            if (UserCache.dbdata[Key] != null && UserCache.dbdata[Key] == Value)  return false;

            if (Key.Length + Value.Length > MaxCookieLen)
            {
                UserCache.dbdata[Key] = Value;
                UserCache.dbchanged = true;
                UserCache.hasdb = true;

                if (UserCache.data[Key] != null)
                {
                    UserCache.data.Remove(Key);
                    UserCache.changed = true;
                }
            }
            else
            {
                UserCache.data[Key] = Value;
                UserCache.changed = true;

                if (UserCache.dbdata[Key] != null)
                {
                    UserCache.dbdata.Remove(Key);
                    UserCache.dbchanged = true;
                    UserCache.hasdb = (UserCache.dbdata.Count > 0);
                }
            }

            return true;
        }

        public void SaveUserInfo()
        {
            SaveUserInfo(false);
        }

        public void SaveUserInfo(bool UseDB)
        {
            if (UserCache.changed)
            {
                JObject CDataObj = new JObject();
                CDataObj["c"] = UserCache.ts;
                CDataObj["s"] = UserInfo.sso_id;
                CDataObj["i"] = UserInfo.id;
                CDataObj["e"] = UserInfo.extra;
                if (UserInfo.tag_map.Count > 0)
                {
                    JObject TagMap = new JObject();
                    foreach (string Key in UserInfo.tag_map)  TagMap[Key] = UserInfo.tag_map[Key];
                    CDataObj["t"] = TagMap;
                }
                if (UserInfo.admin)  CDataObj["a"] = 1;
                if (UseDB && UserCache.hasdb)  CDataObj["b"] = 1;
                if (UserCache.data.Count > 0)
                {
                    JObject DataMap = new JObject();
                    foreach (string Key in UserCache.data)  DataMap[Key] = UserCache.data[Key];
                    CDataObj["d"] = DataMap;
                }
                CDataObj["p"] = UserCache.ipaddr;

                byte[] CData2 = Compress(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(CDataObj)));
                byte[] CData = new byte[CData2.Length + 2];
                CData[0] = (byte)'1';
                CData[1] = (byte)':';
                System.Buffer.BlockCopy(CData2, 0, CData, 2, CData2.Length);

                byte[] APIKey = Encoding.UTF8.GetBytes(Config["server_apikey"]);
                CData2 = new byte[CData.Length + 1 + APIKey.Length];
                System.Buffer.BlockCopy(CData, 0, CData2, 0, CData.Length);
                CData2[CData.Length] = (byte)':';
                System.Buffer.BlockCopy(APIKey, 0, CData2, CData.Length + 1, APIKey.Length);
                string VData;
                using (HMACSHA1 TempHMAC = new HMACSHA1(ConvertHexToBytes(Config["rand_seed6"])))
                {
                    TempHMAC.ComputeHash(CData2);
                    VData = Convert.ToBase64String(TempHMAC.Hash).Replace('+', '-').Replace('/', '_').Replace("=", "");
                }

                NameValueCollection Options = new NameValueCollection();
                Options["mode"] = "CBC";
                Options["iv"] = Config["rand_seed2"];
                Options["key2"] = Config["rand_seed4"];
                Options["iv2"] = Config["rand_seed5"];
                Options["lightweight"] = "true";

                string CData3 = Convert.ToBase64String(AES_CreateDataPacket(CData, Config["rand_seed"], Options)).Replace('+', '-').Replace('/', '_').Replace("=", "");

                if (RequestVars[Config["cookie_name"] + "_c"] == null)  SetCookieFixDomain(Config["cookie_name"] + "_c", "1", DateTime.MinValue, Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), false);
                if (RequestVars[Config["cookie_name"] + "_s"] == null || RequestVars[Config["cookie_name"] + "_s"] != CData3)  SetCookieFixDomain(Config["cookie_name"] + "_s", CData3, (Convert.ToInt32(Config["cookie_timeout"]) > 0 ? DateTime.Now.AddSeconds(Convert.ToInt32(Config["cookie_timeout"])) : DateTime.MinValue), Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), false);
                if (RequestVars[Config["cookie_name"] + "_v"] == null || RequestVars[Config["cookie_name"] + "_v"] != VData)  SetCookieFixDomain(Config["cookie_name"] + "_v", VData, (Convert.ToInt32(Config["cookie_timeout"]) > 0 && Config["cookie_exit_timeout"] == "0" ? DateTime.Now.AddSeconds(Convert.ToInt32(Config["cookie_timeout"])) : DateTime.MinValue), Config["cookie_path"], "", (Config["cookie_ssl_only"] == "1"), false);

                UserCache.changed = false;
            }
        }

        public string GetUserID()
        {
            return UserInfo.id;
        }

        public string GetSecretToken()
        {
            string Data = Config["rand_seed16"] + ":" + Config["cookie_name"] + ":" + HttpContext.Current.Request.PhysicalApplicationPath + ":" + UserInfo.extra;
            string Result;
            using (HMACSHA1 TempHMAC = new HMACSHA1(ConvertHexToBytes(Config["rand_seed15"])))
            {
                TempHMAC.ComputeHash(Encoding.UTF8.GetBytes(Data));
                Result = ConvertBytesToHex(TempHMAC.Hash);
            }

            return Result;
        }
    }
}
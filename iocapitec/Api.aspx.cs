using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace iocapitec
{
    public partial class Api : System.Web.UI.Page
    {
        private static string logdbcn = ConfigurationManager.ConnectionStrings["liveperson"].ConnectionString;
        private static string skill = ConfigurationManager.AppSettings["skill"];
        private static string customerKey = ConfigurationManager.AppSettings["customerKey"];
        private static string customerSecret = ConfigurationManager.AppSettings["customerSecret"];
        private static string tokenKey = ConfigurationManager.AppSettings["tokenKey"];
        private static string tokenSecret = ConfigurationManager.AppSettings["tokenSecret"];
        private static string eligibilityendpoint = ConfigurationManager.AppSettings["eligibilityendpoint"];
        private static string inviteendpoint = ConfigurationManager.AppSettings["inviteendpoint"];
        private static string handoffid = ConfigurationManager.AppSettings["handoffid"];
        private static string GetSignatureBaseString(string strUrl, string strMethod, string TimeStamp,
            string Nonce, string strConsumer, string strOauthToken, SortedDictionary<string, string> data)
        {
            //1.Convert the HTTP Method to uppercase and set the output string equal to this value.
            string Signature_Base_String = strMethod.ToUpper();
            Signature_Base_String = Signature_Base_String.ToUpper();

            //2.Append the ‘&’ character to the output string.
            Signature_Base_String = Signature_Base_String + "&";

            //3.Percent encode the URL and append it to the output string.
            var queryparams = strUrl.IndexOf("?") > strUrl.IndexOf("/") ? strUrl.Substring(strUrl.IndexOf("?") + 1) : "";
            if (queryparams != "")
            {
                strUrl = strUrl.Substring(0, strUrl.IndexOf("?"));
            }
            string PercentEncodedURL = Uri.EscapeDataString(strUrl);
            Signature_Base_String = Signature_Base_String + PercentEncodedURL;
            if (queryparams != null)
            {
                if (data == null)
                {
                    data = new SortedDictionary<string, string>();
                }
                var nvc = System.Web.HttpUtility.ParseQueryString(queryparams);
                foreach (var elt in nvc.AllKeys.ToDictionary(k => k, k => nvc[k]))
                {
                    data.Add(elt.Key, elt.Value);
                }
            }
            //4.Append the ‘&’ character to the output string.
            Signature_Base_String = Signature_Base_String + "&";

            //5.append OAuth parameter string to the output string.
            var parameters = new SortedDictionary<string, string>
            {
                {"oauth_consumer_key", strConsumer},
                { "oauth_token", strOauthToken },
                {"oauth_signature_method", "HMAC-SHA1"},
                {"oauth_timestamp", TimeStamp},
                {"oauth_nonce", Nonce},
                {"oauth_version", "1.0"}
            };

            //6.append parameter string to the output string.
            if (data != null)
            {
                foreach (KeyValuePair<string, string> elt in data)
                {
                    parameters.Add(elt.Key, elt.Value);
                }
            }

            bool first = true;
            foreach (KeyValuePair<string, string> elt in parameters)
            {
                if (first)
                {
                    Signature_Base_String = Signature_Base_String + Uri.EscapeDataString(elt.Key + "=" + elt.Value);
                    first = false;
                }
                else
                {
                    Signature_Base_String = Signature_Base_String + Uri.EscapeDataString("&" + elt.Key + "=" + elt.Value);
                }
            }

            return Signature_Base_String;
        }
        private static string GetSha1Hash(string key, string sbase)
        {
            var encoding = new System.Text.ASCIIEncoding();

            byte[] keyBytes = encoding.GetBytes(key);
            byte[] messageBytes = encoding.GetBytes(sbase);

            string strSignature = string.Empty;

            using (HMACSHA1 SHA1 = new HMACSHA1(keyBytes))
            {
                var Hashed = SHA1.ComputeHash(messageBytes);
                strSignature = Convert.ToBase64String(Hashed);
            }

            return strSignature;
        }

        public static String GetTimestamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        private static string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        private static Random random = new Random();

        public static string GenerateNonce(int length)
        {
            var nonceString = new StringBuilder();
            var random = new Random();
            for (int i = 0; i < length; i++)
            {
                nonceString.Append(validChars[random.Next(0, validChars.Length - 1)]);
            }
            return nonceString.ToString();
        }

        private static System.Data.Common.DbConnection sqlcn = dbconnection();
        private static System.Data.Common.DbConnection dbconnection()
        {
            try
            {
                var cndb = Microsoft.Data.SqlClient.SqlClientFactory.Instance.CreateConnection();
                cndb.ConnectionString = logdbcn;
                cndb.Open();
                LogMessage("info:", "dbconnection()", "db-connected");
                return (System.Data.Common.DbConnection)cndb;
            } catch (Exception ex)
            {
                LogMessage("err:", "dbconnection()", ex.Message);
            }
            return null;
        }

        public static void LogInfo(string url, string postcontent,string responsecontent, string guid,string error, params string[] args)
        {

            if ((sqlcn = sqlcn == null ? dbconnection() : sqlcn) != null)
            {
                var sqlcmd = sqlcn.CreateCommand();
                try
                {
                    sqlcmd.CommandText = "INSERT INTO IVR_liveperson_log(GUID,URL,POSTCONTENT,ARGS,ERROR,RESPONSE) SELECT @GUID,@URL,@POSTCONTENT,@ARGS,@ERROR,@RESPONSE";

                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("URL", url));
                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("POSTCONTENT", postcontent));
                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("GUID", guid));
                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("ERROR", error));
                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("RESPONSE", responsecontent));

                    var argsfnd = "";
                    if (args != null)
                    {

                        foreach (var arg in args)
                        {
                            argsfnd += arg + ";";
                        }
                    }
                    sqlcmd.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("ARGS", argsfnd));
                    sqlcmd.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    if (ex != null)
                    {
                        LogMessage("info" + error == "" ? "" : "-err", guid + "LogInfo()", "url:" + url, "postcontent:" + postcontent, "response:" + responsecontent, error == "" ? "" : error);
                        LogMessage("err", guid + "LogInfo()", ex.Message);
                    }
                }
                finally
                {
                    try
                    {
                        sqlcmd.Dispose();
                    }
                    catch (Exception exs)
                    {
                        
                    }
                }
            } else
            {
                LogMessage("info" + error == "" ? "" : "-err", guid + "LogInfo()", "url:" + url, "postcontent:" + postcontent, "response:" + responsecontent, error == "" ? "" : error);
            }
        }
        private static string nextGuid()
        {
            return Guid.NewGuid().ToString();
        }

        public static string RequestWhatsApp(string ConsumerKey, string ConsumerSecret, string Token, string TokenSecret, string eligibilityurl, string invokeurl, string skill, string handoffid, string cellnumber)
        {
            string outcome = "";
            var timestamp = GetTimestamp();
            var nonce = GenerateNonce(32);

            var URL = eligibilityurl;
            var signaturebase = GetSignatureBaseString(URL, "POST", timestamp, nonce, ConsumerKey, Token, null);
            var authSignature = Uri.EscapeDataString(GetSha1Hash(ConsumerSecret + "&" + TokenSecret, signaturebase)); //"%2FAxSMtS2gYxxRvllSWSSip2lkCs%3D";
            var request = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(URL);

            var authstring = "OAuth oauth_consumer_key=\"" + ConsumerKey + "\", oauth_nonce=\"" + nonce + "\", oauth_signature=\"" + authSignature + "\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + timestamp + "\", oauth_token=\"" + Token + "\", oauth_version=\"1.0\"";
            request.Headers.Add("Authorization", authstring);
            request.ContentType = "application/json";
            request.Method = "POST";

            Dictionary<string, Object> settings = new Dictionary<string, object>();
            settings["skill"] = skill;
            settings["consumerPhoneNumber"] = cellnumber;
            settings["handoffId"] = handoffid;
            string body = JsonConvert.SerializeObject(settings);
            request.ContentLength = body.Length;
            //request.Content = new System.Net.Http.StringContent("{\"skill\": \"WhatsApp_Test\", \"consumerPhoneNumber\": \"+27724407680\", \"handoffId\": \"H165256433774517\"}",Encoding.UTF8,"application/json");

            var nguid = nextGuid();

            try
            {
                using (var strmrqst = new System.IO.StreamWriter(request.GetRequestStream()))
                {
                    strmrqst.Write(body);
                    strmrqst.Flush();
                }
                
                using (var resp = (System.Net.HttpWebResponse)request.GetResponse())
                {

                    try
                    {
                        if (resp.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            var respnse = "";
                            
                            using (var strmrsp = new System.IO.StreamReader(resp.GetResponseStream()))
                            {
                                respnse = strmrsp.ReadToEnd();
                            }
                            LogInfo(URL, body,respnse,nguid,"");

                            var desobj = JsonConvert.DeserializeObject<System.Collections.IDictionary>(respnse);
                            var iseligible = false;
                            var eligiblechannels = new List<string>();
                            var callid = "";
                            foreach (System.Collections.DictionaryEntry elm in (System.Collections.IDictionary)desobj)
                            {
                                var key = elm.Key;
                                var val = elm.Value;
                                if (val.GetType().ToString().Equals("Newtonsoft.Json.Linq.JArray"))
                                {
                                    var arr = ((Newtonsoft.Json.Linq.JArray)val).ToArray();
                                    if (arr.Length > 0)
                                    {
                                        foreach (var chnl in arr)
                                        {
                                            eligiblechannels.Add(chnl.ToObject<string>());
                                        }
                                    }
                                }
                                else if (key.Equals("eligible"))
                                {
                                    iseligible = (bool)val;
                                }
                                else if (key.Equals("callId"))
                                {
                                    callid = (string)val;
                                }

                            }

                            if (iseligible && eligiblechannels.Contains("wa") && !callid.Equals(""))
                            {
                                settings.Clear();
                                settings["callId"] = callid;
                                URL = invokeurl;
                                signaturebase = GetSignatureBaseString(URL, "POST", timestamp, nonce, ConsumerKey, Token, null);
                                authSignature = Uri.EscapeDataString(GetSha1Hash(ConsumerSecret + "&" + TokenSecret, signaturebase));

                                request = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(URL);
                                request.KeepAlive = false;
                                request.ServicePoint.ConnectionLimit = 1;
                                request.Method = "POST";
                                authstring = "OAuth oauth_consumer_key=\"" + ConsumerKey + "\", oauth_nonce=\"" + nonce + "\", oauth_signature=\"" + authSignature + "\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + timestamp + "\", oauth_token=\"" + Token + "\", oauth_version=\"1.0\"";
                                request.Headers.Add("Authorization", authstring); 
                                request.ContentType = "application/json";
                                body = JsonConvert.SerializeObject(settings);
                                using (var strmrqst = new System.IO.StreamWriter(request.GetRequestStream()))
                                {
                                    strmrqst.Write(body);
                                    strmrqst.Flush();
                                }
                                using (var respinit = (System.Net.HttpWebResponse)request.GetResponse())
                                {
                                    respnse = "";
                                    if (resp.StatusCode == System.Net.HttpStatusCode.OK)
                                    {
                                        using (var strmrsp = new System.IO.StreamReader(respinit.GetResponseStream()))
                                        {
                                            respnse = strmrsp.ReadToEnd();
                                        }
                                        LogInfo(URL, body, respnse, nguid, "");
                                        if (respnse.Contains(callid))
                                        {
                                            outcome = "callId:" + callid;
                                        }
                                    }
                                    else
                                    {
                                        outcome = "failed:" + resp.StatusCode;
                                    }
                                }
                            }
                            else
                            {
                                outcome = "not-eligible";
                            }
                        }
                        else
                        {
                            outcome = "failed:" + resp.StatusCode;
                        }
                    }
                    catch (Exception e)
                    {
                        var err = e.StackTrace;
                        LogInfo(URL, body, "", nguid, err);
                        outcome = "error:" +err;
                    }
                }
            }
            catch (Exception e)
            {
                var err = e.InnerException.Message;
                LogInfo(URL, body, "", nguid, err);
                outcome = "error:" + err;
            }
            return outcome;
        }
        protected void Page_Load(object sender, EventArgs e)
        {
            var ani = this.Request.QueryString.Get("ANI");
            var output = "";
            if (ani==null || ani.Equals("")) {
                output = "failed: no ani";
            } else
            {
                var newani = "";
                foreach(var ac in ani.ToCharArray())
                {
                    if (ac>='0' && ac<='9')
                    {
                        newani += ac;
                    }
                }
                while (newani.StartsWith("0")) newani = newani.Substring(1);
                if (newani.Equals(""))
                {
                    output = "failed: invalid ani";
                } else
                {
                    if (newani.Length < 9)
                    {
                        output = "failed: invalid ani";
                    }
                    else
                    {
                        if (newani.Length == 9)
                        {
                            newani = "27" + newani;
                        }
                        if (!newani.StartsWith("+"))
                        {
                            newani = "+" + newani;
                        }
                    }
                    ani = newani;
                    output = RequestWhatsApp(customerKey, customerSecret, tokenKey, tokenSecret, eligibilityendpoint, inviteendpoint, skill, handoffid, ani);
                }
            }
            this.Response.Write(output);
        }

        private static System.IO.StreamWriter logstrm = null;
        
        public static void LogMessage(string msgtype,params string[] args)
        {
            var logfilename = System.AppDomain.CurrentDomain.BaseDirectory+ "livepersonapi." + DateTime.Now.ToString("yyyy-MM-dd") + ".log";
            if (!System.IO.File.Exists(logfilename))
            {
                if (logstrm!=null)
                {
                    logstrm.Flush();
                    logstrm.Close();
                }
                if (logstrm == null)
                {
                    try
                    {
                        logstrm = new System.IO.StreamWriter(logfilename, true);
                    } catch(Exception ex)
                    {

                    }
                }
            } else
            {
                if (logstrm == null)
                {
                    try
                    {
                        logstrm = new System.IO.StreamWriter(logfilename, true);
                    }
                    catch (Exception ex)
                    {

                    }
                }
            }
            if (logstrm != null)
            {
                logstrm.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + msgtype + string.Join(" ", args));
                logstrm.Flush();
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Data.SQLite;
using System.Net;
using Microsoft.VisualBasic.CompilerServices;
using Microsoft.VisualBasic;

namespace BEKeyCheck
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        CopyRP.Key arma2key = new CopyRP.Key();
        private static Random random = new Random();
        List<string> goodkeys = new List<string>();

        private void button1_Click(object sender, EventArgs e)
        {
            using (SQLiteConnection dbCon = new SQLiteConnection("Data Source=keys.sqlite;Version=3;"))
            {
                try
                {
                    dbCon.Open();
                    string query = "SELECT count(key) FROM keys WHERE status='not';";
                    string query1 = "SELECT * FROM keys WHERE status='not';";
                    int rowcount = 0;
                    using (SQLiteCommand command = new SQLiteCommand(query, dbCon))
                    {
                        rowcount = Convert.ToInt32(command.ExecuteScalar());
                        label1.Text = rowcount.ToString();
                    }
                    if (rowcount != 1)
                    {
                        using (SQLiteCommand cmd = new SQLiteCommand(query1, dbCon))
                        {
                            using (SQLiteDataReader reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    Console.WriteLine(reader["key"]);
                                    banCheck(reader["key"].ToString(), true, dbCon);
                                }
                            }
                        }
                    }
                    //MessageBox.Show(rowcount.ToString());
                    dbCon.Close();
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("was closed"))
                    {
                        dbCon.Open();
                    }
                    Console.WriteLine(ex.Message + "button1 check");
                }
            }
        }

        private string banStatus(string key)
        {
            using (MD5 md5hash = MD5.Create())
            {
                string hash = GetMd5Hash(md5hash, key);
                string actualhash = GetMd5Hash(md5hash, "BE" + hash);
                string test = HexString(actualhash);
                //Console.WriteLine(test);
                string last = HexToBin("b1fbe207" + test);
                //Console.WriteLine(last);
                string str4;
                try
                {
                    UdpClient client = new UdpClient(64378);
                    IPEndPoint remoteEP = new IPEndPoint(IPAddress.Any, 100);
                    byte[] bytes = Encoding.ASCII.GetBytes(last);
                    int length4 = bytes.Length;
                    Console.WriteLine("Packet being sent");
                    client.Send(bytes, length4, "arma2oa1.battleye.com", 2324);
                    Console.WriteLine("awaiting response");
                    str4 = Encoding.ASCII.GetString(client.Receive(ref remoteEP));
                    Console.WriteLine("Response: " + str4);
                    client.Close();
                }
                catch (Exception ex)
                {
                    str4 = "Error";
                    Console.WriteLine(ex.ToString());
                }
                return str4;
            }
        }

        private void banCheck(string key, bool update, SQLiteConnection con)
        {
            if (con == null)
            {
                con = new SQLiteConnection("Data Source=keys.sqlite;Version=3;");
            }
            string str4 = banStatus(key);
            if (!str4.Contains("Ban"))
            {
                if (!update)
                {
                    updateDB(key);
                }
            }
            else
            {
                try
                {
                    if (con.State.ToString() != "Open")
                    {
                        con.Open();
                    }
                    
                    string query;
                    if (!update)
                    {
                        query = "INSERT INTO keys (key, status) VALUES ('" + key + "', 'banned');";
                    }
                    else
                    {
                        query = "UPDATE keys SET status='banned' WHERE key='" + key + "';";
                    }
                    using (SQLiteCommand command = new SQLiteCommand(query, con))
                    {
                        command.ExecuteNonQuery();
                    }
                    //con.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString() + " ban check");
                }
                finally
                {
                    //con.Close();
                }
            }
        }

        static string GetMd5Hash(MD5 md5Hash, string input)
        {

            // Convert the input string to a byte array and compute the hash. 
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes 
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data  
            // and format each one as a hexadecimal string. 
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string. 
            return sBuilder.ToString();
        }

        private static string GetMD5Hash(string input)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }
            return sb.ToString().ToLower();
        }


        private void button2_Click(object sender, EventArgs e)
        {
            arma2key.HexData = textBox1.Text;
            MessageBox.Show(arma2key.CDKey);
        }

        private string HexString(string EvalString)
        {
            char[] chArray1 = EvalString.ToCharArray();
            string str = "";
            char[] chArray2 = chArray1;
            int index = 0;
            while (index < chArray2.Length)
            {
                char ch = chArray2[index];
                str = str + Conversion.Hex(Convert.ToSByte(ch));
                checked { ++index; }
            }
            return str;
        }

        private string HexToBin(string HexString)
        {
            int length = HexString.Length;
            char[] chArray = HexString.ToCharArray();
            string str1 = "";
            string Left = "";
            int index = 0;
            while (index < length)
            {
                if (Operators.CompareString(Left, "", false) == 0)
                {
                    Left = Conversions.ToString(chArray[index]);
                }
                else
                {
                    string str2 = Left + Conversions.ToString(chArray[index]);
                    str1 = str1 + Conversions.ToString(Microsoft.VisualBasic.Strings.ChrW(Convert.ToInt32(str2, 16)));
                    Left = "";
                }
                checked { ++index; }
            }
            return str1;
        }

        private static string GetRequestString(string cdKey)
        {
            string serverToken = RandomString(8);
            int clientToken = NextInt(32);
            int ip = NextInt(32);
            int skey = NextInt(8);
            string req = GetMD5Hash(cdKey) + clientToken.ToString("x") + GetMD5Hash(cdKey + GetModulo(clientToken, 0xffff) + serverToken);
            string str = "";
            str += @"\auth\\pid\3045\ch\" + serverToken;
            str += @"\resp\" + req;
            str += @"\ip\" + NextInt(6);
            str += @"\skey\" + skey;
            return str;
        }

        private static string GamespyXOR(string text)
        {
            var result = new StringBuilder();
            string key = "gamespy";
            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ (uint)key[c % key.Length]));
            return result.ToString();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            foreach (string a in goodkeys)
            {
                updateDB(a);
            }
        }

        public void checkKeys(string key)
        {
            string response = GetResponse(key);
            Console.WriteLine(response);
            if (response.Contains("uok"))
            {
                //listBox1.Items.Add(key);
                banCheck(key, false, null);
            }
            else if (response.Contains("Bad Response"))
            {
                checkKeys(key);
            }
            else if (response.Contains("CD Key in use"))
            {
                banCheck(key, false, null);
            }
            else if (response.Contains("Invalid"))
            {
                using (SQLiteConnection dbCon = new SQLiteConnection("Data Source=keys.sqlite;Version=3;"))
                {
                    try
                    {
                        dbCon.Open();
                        string query = "INSERT INTO keys (key, status) VALUES ('" + key + "', 'invalid');";
                        SQLiteCommand command = new SQLiteCommand(query, dbCon);
                        command.ExecuteNonQuery();
                        dbCon.Close();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message + "Invalid check");
                    }
                }
            }
        }

        public static string GetResponse(String key)
        {
            try
            {
                byte[] data = new byte[2048];
                IPEndPoint ipep = new IPEndPoint(Dns.GetHostEntry("master.gamespy.com").AddressList.FirstOrDefault(), 29910);
                Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                server.ReceiveTimeout = 5000;
                server.SendTimeout = 5000;
                //Sending string to the gamespy master server

                string req = GetRequestString(key);
                //Console.WriteLine(req);
                data = Encoding.ASCII.GetBytes(GamespyXOR(req));
                server.SendTo(data, data.Length, 0, ipep);

                //Receiving response from the master server
                EndPoint Remote = (EndPoint)new IPEndPoint(IPAddress.Any, 0);
                data = new byte[2048];
                int recv = server.ReceiveFrom(data, ref Remote);
                server.Close();
                return (GamespyXOR(Encoding.ASCII.GetString(data, 0, recv)));
            }
            catch (Exception ex) { }
            return "Timeout";
        }

        public static string RandomString(int Length)
        {
            var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            var result = new string(
                Enumerable.Repeat(chars, Length)
                          .Select(s => s[random.Next(s.Length)])
                          .ToArray());
            return result;
        }

        private static int NextInt(int length)
        {
            var buffer = new byte[length];
            random.NextBytes(buffer);
            int number = BitConverter.ToInt32(buffer, 0);
            if (number < 0)
                number *= -1;
            return number;
        }

        private static double GetModulo(double v, double m)
        {
            if (v < m) return v;
            return v % m;
        }

        private void button4_Click(object sender, EventArgs e)
        {
            string[] keys = File.ReadAllLines("clean2.txt");
            foreach (string s in keys)
            {
                duplicateCheck(s);
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            List<string> keysfromweb = new List<string>();
            int amount = 0;
            using (WebClient wc = new WebClient())
            {
                string data = wc.DownloadString("http://dayzkeys.net63.net/loggers/logs.html").ToUpper();
                data += wc.DownloadString("http://dayzkeys.hostoi.com/loggers/logs.html").ToUpper();
                string[] keys = data.Split(new string[] { "KEY: " }, StringSplitOptions.None);
                foreach (string s in keys)
                {
                    string a = s;
                    int index = a.IndexOf("<BR />");
                    if (index > 0)
                    {
                        a = a.Substring(0, index);
                        //Console.WriteLine(a);
                        duplicateCheck(a);
                    }
                }
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void updateDB(string key)
        {
            using (SQLiteConnection dbCon = new SQLiteConnection("Data Source=keys.sqlite;Version=3;"))
            {
                try
                {
                    dbCon.Open();
                    string query = "INSERT INTO keys (key, status) VALUES ('" + key + "', 'not');";
                    SQLiteCommand command = new SQLiteCommand(query, dbCon);
                    command.ExecuteNonQuery();
                    dbCon.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message + "Update DB");
                }
            }
        }

        private void duplicateCheck(string key)
        {
            using (SQLiteConnection dbCon = new SQLiteConnection("Data Source=keys.sqlite;Version=3;"))
            {
                try
                {
                    dbCon.Open();
                    string query = "SELECT count(key) FROM keys WHERE key='" + arma2key.GetCDKey(key) + "';";
                    int rowcount = 0;
                    SQLiteCommand command = new SQLiteCommand(query, dbCon);
                    rowcount = Convert.ToInt32(command.ExecuteScalar());
                    if (rowcount != 1)
                    {
                        checkKeys(arma2key.GetCDKey(key));
                    }
                    dbCon.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message + "Duplicate check");
                }
            }
        }
    }
}

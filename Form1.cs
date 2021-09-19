using Org.Mentalis.Network.ProxySocket;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
namespace MS_CHECK_PARSER
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        struct LogType
        {
            public string date;
            public int logtype;
            public string[] strdata;
        }

        List<LogType> LogList = new List<LogType>();

        struct IPCHECK
        {
            public string ipaddr;
            public bool detected;
        }

        List<IPCHECK> iPCHECKs = new List<IPCHECK>();
        private readonly object iPCHECKsLock = new object();
        private readonly object iPCHECKsLock2 = new object();

        int GetIpCheckResult(string str)
        {
            lock (iPCHECKsLock)
            {
                foreach (var ipc in iPCHECKs)
                {
                    if (ipc.ipaddr == str)
                        return ipc.detected ? 2 : 1;
                }
            }
            return 0;
        }
        void AddCheckIp(string str, bool detected)
        {
            lock (iPCHECKsLock)
            {
                foreach (var ipc in iPCHECKs)
                {
                    if (ipc.ipaddr == str)
                        return;
                }

                IPCHECK iPCHECK = new IPCHECK();
                iPCHECK.ipaddr = str;
                iPCHECK.detected = false;
                iPCHECKs.Add(iPCHECK);
            }
        }

        struct LogItem
        {
            public string ms_name;
            public string steamid;
            public string ipaddr;
        }

        LogItem ParseStringToLogItem(string str2)
        {
            LogItem tmpLogItem = new LogItem();
            string str = str2.Remove(0, str2.IndexOf("\"") + 1);
            str = str.Remove(0, str.IndexOf("\"") + 1);
            str = str.Remove(0, str.IndexOf("\"") + 1);
            tmpLogItem.ms_name = str.Remove(str.IndexOf("\""));
            str = str.Remove(0, str.IndexOf("\"") + 1);
            str = str.Remove(0, str.IndexOf("\"") + 1);
            tmpLogItem.steamid = str.Remove(str.IndexOf("\""));
            str = str.Remove(0, str.IndexOf("\"") + 1);
            str = str.Remove(0, str.IndexOf("\"") + 1);
            tmpLogItem.ipaddr = str.Remove(str.IndexOf("\""));
            return tmpLogItem;
        }

        bool endsearchproxies = false;
        struct LogUnique
        {
            public bool DetectProxyStarted;
            public bool DetectProxyEnded;
            public bool ProxyDetected;
            public string date;
            public string ms_name;
            public string steamid;
            public string ipaddress;
            public int date_count;
            public int global_count;
        }

        List<LogUnique> UniqueList = new List<LogUnique>();

        struct DetectedProxies
        {
            public string ms_name;
            public int count;
        }

        List<DetectedProxies> DetectedProxiesList = new List<DetectedProxies>();

        int proxiesstarted = 0;
        int proxiesschecked = 0;
        int proxiesdetected = 0;
        public static readonly byte[] REQUEST = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0xFF, 0xFF, 0xFF, 0xFF };


        void DetectProxyProxy()
        {
            for (int i = 0; i < UniqueList.Count; i++)
            {
                var tmpUnique = UniqueList[i];
                if (UniqueList[i].DetectProxyStarted)
                {
                    continue;
                }
                tmpUnique.DetectProxyStarted = true;
                UniqueList[i] = tmpUnique;

                int proxydetectedtype = GetIpCheckResult(tmpUnique.ipaddress);
                if (proxydetectedtype == 0)
                {
                    if (!tmpUnique.ProxyDetected)
                    {
                        Thread.Sleep(10);
                        tmpUnique.ProxyDetected = IsProxyWorks(tmpUnique.ipaddress, 8080);
                    }
                    if (!tmpUnique.ProxyDetected)
                    {
                        Thread.Sleep(10);
                        tmpUnique.ProxyDetected = IsProxyWorks(tmpUnique.ipaddress, 1080);
                    }
                    if (!tmpUnique.ProxyDetected)
                    {
                        Thread.Sleep(10);
                        UdpClient udp = new UdpClient();
                        IPAddress ip;
                        if (!IPAddress.TryParse(tmpUnique.ipaddress, out ip))
                        {
                            MessageBox.Show("Error parse ip address:" + tmpUnique.ipaddress);
                        }
                        else
                        {
                            try
                            {
                                var ep = new IPEndPoint(ip, 27015);

                                udp.Client.SendTimeout = 1500;
                                udp.Client.ReceiveTimeout = 1500;

                                udp.Send(REQUEST, REQUEST.Length, ep); // Request Challenge.
                                byte[] challenge_response = udp.Receive(ref ep);
                                if (challenge_response.Length > 0)
                                {
                                    tmpUnique.ProxyDetected = true;
                                }
                            }
                            catch
                            {

                            }
                        }
                        try
                        {
                            udp.Close();
                        }
                        catch
                        {

                        }
                    }
                    lock (iPCHECKsLock2)
                    {
                        if (tmpUnique.ProxyDetected)
                        {
                            proxiesdetected++;
                        }
                    }
                }
                else
                {
                    tmpUnique.ProxyDetected = proxydetectedtype == 2;
                }
                AddCheckIp(tmpUnique.ipaddress, tmpUnique.ProxyDetected);
                tmpUnique.DetectProxyEnded = true;
                UniqueList[i] = tmpUnique;
                lock (iPCHECKsLock2)
                {
                    proxiesschecked++;
                }
            }
            lock (iPCHECKsLock2)
            {
                proxiesstarted--;
            }
        }

        void CheckAllProxies()
        {
            while (true)
            {
                while (proxiesstarted > 100)
                    Thread.Sleep(150);
                Thread.Sleep(100);
                bool NeedCheckProxy = false;
                for (int i = 0; i < UniqueList.Count; i++)
                {
                    if (!UniqueList[i].DetectProxyEnded)
                    {
                        NeedCheckProxy = true;
                        break;
                    }
                }
                if (NeedCheckProxy)
                {
                    for (int i = 0; i < 150; i++)
                    {
                        proxiesstarted++;
                        new Thread(DetectProxyProxy).Start();
                    }
                }
                else break;
            }

            foreach (var unik in UniqueList)
            {
                if (File.Exists("unik_" + unik.date + ".log"))
                    File.Delete("unik_" + unik.date + ".log");
            }

            foreach (var unik in UniqueList)
            {
                File.AppendAllText("unik_" + unik.date + ".log", unik.ipaddress + "|" + unik.ms_name + "|" + (unik.ProxyDetected ? "PROXY" : "REAL PLAYER") + "\n");
            }
            endsearchproxies = true;
            MessageBox.Show("Proxies:" + proxiesdetected);
        }

        int possibleproxy = 0;
        int possibleproxy2 = 0;


        private bool IsProxyWorks(string url, int port)
        {
            try
            {
                // create a new ProxySocket
                ProxySocket s = new ProxySocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                s.ReceiveTimeout = 3000;
                s.SendTimeout = 3000;
                // set the proxy settings
                s.ProxyEndPoint = new IPEndPoint(IPAddress.Parse(url), port);
                s.ProxyType = ProxyTypes.Socks5;    // if you set this to ProxyTypes.None, 
                                                    // the ProxySocket will act as a normal Socket
                                                    // connect to the remote server
                                                    // (note that the proxy server will resolve the domain name for us)
                s.Connect("google.com", 80);
                // send an HTTP request
                s.Send(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: google.com\r\n\r\n"));
                // read the HTTP reply
                int recv = 0;
                byte[] buffer = new byte[1024];
                bool found = false;
                recv = s.Receive(buffer);
                if (recv > 0)
                    found = true;
                while (recv > 0)
                {
                    recv = s.Receive(buffer);
                    found = true;
                }
                return found;
            }
            catch (ProxyException ex)
            {
                return true;
            }
            catch (ProtocolViolationException ex)
            {
                return true;
            }
            catch (SocketException ex)
            {
                if (ex.Message.IndexOf("отверг") > 0)
                    possibleproxy++;
                if (ex.Message.IndexOf("безуспешной") > 0)
                    possibleproxy2++;
            }
            catch 
            {

            }
            return false;
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            button1.Enabled = false;
            LogList.Clear();
            proxiesdetected = 0;
            proxiesschecked = 0;
            possibleproxy = 0;
            possibleproxy2 = 0;
            endsearchproxies = false;
            UniqueList.Clear();
            DetectedProxiesList.Clear();
            iPCHECKs.Clear();
            var Files = Directory.GetFiles(textBox1.Text, "*.log");
            foreach (var file2 in Files)
            {
                LogType logType = new LogType();
                logType.strdata = File.ReadAllLines(file2);
                string file = file2;
                while (file.IndexOf("\\") >= 0)
                {
                    file = file.Remove(0, file.IndexOf("\\") + 1);
                }
                while (file.IndexOf("/") >= 0)
                {
                    file = file.Remove(0, file.IndexOf("\\") + 1);
                }
                logType.date = file.Replace("ms_log_", "").Replace("ms_other_", "").Replace("ms_unknown_", "").Replace(".log", "");
                logType.logtype = file.IndexOf("ms_log_") >= 0 ? 1 : (file.IndexOf("ms_other_") >= 0 ? 2 : 3);
                LogList.Add(logType);
            }

            MessageBox.Show("Loaded " + LogList.Count + " log files.", "INFO");
            if (LogList.Count > 2)
            {
                // file - текущий лог файл
                // tmpitem - текущая обработанная строка из лог файла
                // unik - уник из списка уников
                foreach (var file in LogList)
                {
                    if (file.logtype == 1)
                    {
                        foreach (var str in file.strdata)
                        {
                            var tmpitem = ParseStringToLogItem(str);
                            bool unikfound = false;
                            for (int i = 0; i < UniqueList.Count; i++)
                            {
                                var unik = UniqueList[i];
                                if (tmpitem.ms_name == unik.ms_name)
                                {
                                    if (tmpitem.ipaddr == unik.ipaddress || tmpitem.steamid == unik.steamid)
                                    {
                                        if (unik.date == file.date) // уник на текущую дату
                                        {
                                            unik.date_count++;
                                            unikfound = true;
                                        }
                                        else
                                        {
                                            unik.global_count++;
                                        }
                                        UniqueList[i] = unik;
                                    }
                                }
                            }
                            if (!unikfound)
                            {
                                LogUnique logUnique = new LogUnique();
                                logUnique.date = file.date;
                                logUnique.date_count = 1;
                                logUnique.global_count = 1;
                                logUnique.ipaddress = tmpitem.ipaddr;
                                logUnique.steamid = tmpitem.steamid;
                                logUnique.ms_name = tmpitem.ms_name;
                                logUnique.DetectProxyStarted = false;
                                logUnique.DetectProxyEnded = false;
                                logUnique.ProxyDetected = false;
                                UniqueList.Add(logUnique);
                            }
                        }
                    }
                }
            }

            MessageBox.Show("Loaded " + UniqueList.Count + " unique connections.", "INFO");
            MessageBox.Show("Start proxies detection! Need 30-60 second for check 1000 uniques!", "INFO");
            new Thread(StatusPrint).Start();
            CheckAllProxies();
            MessageBox.Show("Detect " + proxiesdetected + " proxies. Saved to proxy.log", "INFO " + possibleproxy + " " + possibleproxy2);
            if (File.Exists("proxy.log"))
                File.Delete("proxy.log");

            foreach (var unik in UniqueList)
            {
                if (!unik.ProxyDetected)
                    continue;
                bool unikfound = false;
                for (int i = 0; i < DetectedProxiesList.Count; i++)
                {
                    var proxdetect = DetectedProxiesList[i];
                    if (unik.ms_name == proxdetect.ms_name)
                    {
                        proxdetect.count++;
                        DetectedProxiesList[i] = proxdetect;
                        unikfound = true;
                        break;
                    }
                }
                if (!unikfound)
                {
                    DetectedProxies detectedProxies = new DetectedProxies();
                    detectedProxies.count = 1;
                    detectedProxies.ms_name = unik.ms_name;
                    DetectedProxiesList.Add(detectedProxies);
                }
            }

            for (int i = 0; i < DetectedProxiesList.Count; i++)
            {
                File.AppendAllText("proxy.log", DetectedProxiesList[i].ms_name + " = " + DetectedProxiesList[i].count + "\n");
            }

            button1.Enabled = true;
        }

        private void StatusPrint()
        {
            while (!endsearchproxies)
            {
                Thread.Sleep(1000);
                File.WriteAllText("status.log", "Test " + proxiesschecked + " proxies of " + UniqueList.Count);
            }
        }
    }
}

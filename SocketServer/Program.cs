using log4net;
using SocketServer.Helper;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SocketServer
{
    class Program
    {
        private readonly static ILog _log = LogManager.GetLogger(typeof(Program));

        static void Main(string[] args)
        {
            _log.Info("Socket服务开启");
            string portStr = ConfigurationManager.AppSettings["Port"];
            var socketPort = 8800;
            if (int.TryParse(portStr, out int port))
            {
                socketPort = port;
            }
            if (PortHelper.PortInUse(socketPort, PortType.TCP))
            {
                Console.WriteLine($"{socketPort}端口被占用！");
            }
            else
            {
                string sslFilePath = Environment.CurrentDirectory + "\\" + ConfigurationManager.AppSettings["SslFilePath"];
                string sslPassword = ConfigurationManager.AppSettings["SslPassword"];
                SSLServers.SslServerStart.Start(socketPort, sslFilePath, sslPassword);
            }
        }
    }
}

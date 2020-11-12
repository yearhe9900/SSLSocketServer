using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLServers
{
    class ClientSession : SslSession
    {
        private readonly static ILog _log = LogManager.GetLogger(typeof(ClientSession));

        public ClientSession(SslBaseServer server) : base(server) { }

        protected override void OnConnected()
        {
            Console.WriteLine($"客户端链接成功，分配ID {Id}");
        }

        protected override void OnHandshaked()
        {
            _log.Info($"ID为{Id}的客户端握手成功!");
            Console.WriteLine($"ID为{Id}的客户端握手成功!");
        }

        protected override void OnDisconnected()
        {
            Console.WriteLine($"ID为{Id}的客户端断开连接!");
        }

        /// <summary>
        /// 收发客户端消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            string message = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            Console.WriteLine("收到的消息: " + message);
            //这边可以写收到消息后的处理方法
            _log.Info("收到的消息: " + message);

            // 向指定客户端ID发送消息
            //这边可以写收到消息后的处理方法
            _log.Info("发送的消息: " + message);
            Server.Multicast(message, Id);
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"客户端连接发生错误，错误为{error}");
        }
    }

    class SslServer : SslBaseServer
    {
        public SslServer(SslContext context, IPAddress address, int port) : base(context, address, port) { }

        protected override SslSession CreateSession() { return new ClientSession(this); }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"客户端连接发生错误，错误为{error}");
        }
    }



    public class SslServerStart
    {
        /// <summary>
        /// 总是接受 认证平台 服务器的证书
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="errors"></param>
        /// <returns></returns>
        public static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            return false;
        }

        /// <summary>
        /// 服务开启
        /// </summary>
        /// <param name="port">Scoket端口号</param>
        /// <param name="sslFilePath">PFX证书路径</param>
        /// <param name="sslPassword"></param>
        public static void Start(int port, string sslFilePath, string sslPassword)
        {
            Console.WriteLine($"启动端口：{port} 监听");

            var context = new SslContext(SslProtocols.Tls12, new X509Certificate2(sslFilePath, sslPassword));

            // 创建一个新的Socket ssl服务
            var server = new SslServer(context, IPAddress.Any, port);

            Console.WriteLine("服务正在启动...");
            server.Start();
            Console.WriteLine("服务启动完成!");

            Console.WriteLine("输入'stop'停止服务或输入'restart'重启服务");

            for (; ; )
            {
                string line = Console.ReadLine();
                if (line == "stop")
                    break;

                if (line == "restart")
                {
                    Console.WriteLine("服务重启中...");
                    server.Restart();
                    Console.WriteLine("服务重启完成!");
                    continue;
                }
            }

            Console.WriteLine("服务停止中...");
            server.Stop();
            Console.WriteLine("服务停止完成!");
            Console.ReadKey();
        }
    }
}

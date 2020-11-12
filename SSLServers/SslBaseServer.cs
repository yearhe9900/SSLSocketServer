using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SSLServers
{
    /// <summary>
    /// Ssl Scoket服务
    /// </summary>
    public class SslBaseServer : IDisposable
    {
        /// <summary>
        /// 初始化一个Socket服务，填入地址和端口
        /// </summary>
        /// <param name="context"></param>
        /// <param name="address"></param>
        /// <param name="port"></param>
        public SslBaseServer(SslContext context, IPAddress address, int port) : this(context, new IPEndPoint(address, port)) { }

        /// <summary>
        /// 初始化一个Socket服务，填入地址和端口
        /// </summary>
        /// <param name="context"></param>
        /// <param name="address"></param>
        /// <param name="port"></param>
        public SslBaseServer(SslContext context, string address, int port) : this(context, new IPEndPoint(IPAddress.Parse(address), port)) { }

        public SslBaseServer(SslContext context, IPEndPoint endpoint)
        {
            Id = Guid.NewGuid();
            Context = context;
            Endpoint = endpoint;
        }

        /// <summary>
        /// Server Id
        /// </summary>
        public Guid Id { get; }

        /// <summary>
        /// SSL 上下文
        /// </summary>
        public SslContext Context { get; private set; }

        public IPEndPoint Endpoint { get; private set; }

        /// <summary>
        /// Socket 客户端连接数
        /// </summary>
        public long ConnectedSessions { get { return Sessions.Count; } }

        //public long BytesPending { get { return _bytesPending; } }

        //public long BytesSent { get { return _bytesSent; } }

        //public long BytesReceived { get { return _bytesReceived; } }

        /// <summary>
        /// 配置项: 消息接收字符数
        /// </summary>
        public int OptionAcceptorBacklog { get; set; } = 1024;

        /// <summary>
        /// 配置项:获取或设置一个 System.Boolean 值，该值指定 System.Net.Sockets.Socket 是否是用于 IPv4 和 IPv6 的双模式套接字。
        /// </remarks>
        public bool OptionDualMode { get; set; } = false;

        /// <summary>
        /// 配置项:是否保持存活
        /// </summary>
        public bool OptionKeepAlive { get; set; }

        public bool OptionNoDelay { get; set; }

        public bool OptionReuseAddress { get; set; }

        public bool OptionExclusiveAddressUse { get; set; }

        public int OptionReceiveBufferSize { get; set; } = 8192;

        public int OptionSendBufferSize { get; set; } = 8192;

        #region 开启/关闭 服务

        // Server acceptor
        private Socket _acceptorSocket;
        private SocketAsyncEventArgs _acceptorEventArg;

        // Server statistic
        internal long _bytesPending;
        internal long _bytesSent;
        internal long _bytesReceived;

        public bool IsStarted { get; private set; }

        public bool IsAccepting { get; private set; }

        protected virtual Socket CreateSocket()
        {
            return new Socket(Endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }

        public virtual bool Start()
        {
            if (IsStarted)
                return false;

            _acceptorEventArg = new SocketAsyncEventArgs();
            _acceptorEventArg.Completed += OnAsyncCompleted;

            _acceptorSocket = CreateSocket();

            IsSocketDisposed = false;

            _acceptorSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, OptionReuseAddress);

            _acceptorSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, OptionExclusiveAddressUse);

            if (_acceptorSocket.AddressFamily == AddressFamily.InterNetworkV6)
                _acceptorSocket.DualMode = OptionDualMode;

            _acceptorSocket.Bind(Endpoint);

            Endpoint = (IPEndPoint)_acceptorSocket.LocalEndPoint;

            _acceptorSocket.Listen(OptionAcceptorBacklog);

            _bytesPending = 0;
            _bytesSent = 0;
            _bytesReceived = 0;

            IsStarted = true;

            OnStarted();

            IsAccepting = true;
            StartAccept(_acceptorEventArg);

            return true;
        }

        /// <summary>
        /// 停止服务
        /// </summary>
        /// <returns></returns>
        public virtual bool Stop()
        {
            if (!IsStarted)
                return false;

            IsAccepting = false;

            _acceptorEventArg.Completed -= OnAsyncCompleted;

            _acceptorSocket.Close();

            _acceptorSocket.Dispose();

            _acceptorEventArg.Dispose();

            IsSocketDisposed = true;

            DisconnectAll();

            IsStarted = false;

            OnStopped();

            return true;
        }

        public virtual bool Restart()
        {
            if (!Stop())
                return false;

            while (IsStarted)
                Thread.Yield();

            return Start();
        }

        #endregion

        #region 监听器

        /// <summary>
        /// 启动消息接收监听
        /// </summary>
        /// <param name="e"></param>
        private void StartAccept(SocketAsyncEventArgs e)
        {
            e.AcceptSocket = null;

            if (!_acceptorSocket.AcceptAsync(e))
                ProcessAccept(e);
        }

        private void ProcessAccept(SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.Success)
            {
                var session = CreateSession();

                RegisterSession(session);

                session.Connect(e.AcceptSocket);
            }
            else
                SendError(e.SocketError);

            if (IsAccepting)
                StartAccept(e);
        }

        private void OnAsyncCompleted(object sender, SocketAsyncEventArgs e)
        {
            ProcessAccept(e);
        }

        #endregion

        #region 客户端数据

        protected virtual SslSession CreateSession() { return new SslSession(this); }

        #endregion

        #region 客户端管理

        protected readonly ConcurrentDictionary<Guid, SslSession> Sessions = new ConcurrentDictionary<Guid, SslSession>();

        public virtual bool DisconnectAll()
        {
            if (!IsStarted)
                return false;

            foreach (var session in Sessions.Values)
                session.Disconnect();

            return true;
        }

        public SslSession FindSession(Guid id)
        {
            return Sessions.TryGetValue(id, out SslSession result) ? result : null;
        }

        internal void RegisterSession(SslSession session)
        {
            Sessions.TryAdd(session.Id, session);
        }

        /// <summary>
        /// 移除一个指定的客户端
        /// </summary>
        /// <param name="id"></param>
        internal void UnregisterSession(Guid id)
        {
            _ = Sessions.TryRemove(id, out _);
        }

        #endregion

        #region 消息发送

        /// <summary>
        /// 群发消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual bool Multicast(byte[] buffer) { return Multicast(buffer, 0, buffer.Length); }

        /// <summary>
        /// 向指定的一个客户端发送消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="sessionID"></param>
        /// <returns></returns>
        public virtual bool Multicast(byte[] buffer, Guid sessionID) { return Multicast(buffer, 0, buffer.Length, sessionID); }

        /// <summary>
        /// 向指定的一个客户端发送消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <param name="sessionId"></param>
        /// <returns></returns>
        public virtual bool Multicast(byte[] buffer, long offset, long size, Guid sessionId)
        {
            if (!IsStarted)
                return false;

            if (size == 0)
                return true;

            var session = Sessions[sessionId];
            if (session == null)
                return false;
            session.SendAsync(buffer, offset, size);

            return true;
        }

        /// <summary>
        /// 向所有客户端广播
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public virtual bool Multicast(byte[] buffer, long offset, long size)
        {
            if (!IsStarted)
                return false;

            if (size == 0)
                return true;

            foreach (var session in Sessions.Values)
                session.SendAsync(buffer, offset, size);

            return true;
        }

        public virtual bool Multicast(string text) { return Multicast(Encoding.UTF8.GetBytes(text)); }

        public virtual bool Multicast(string text, Guid sessionID) { return Multicast(Encoding.UTF8.GetBytes(text), sessionID); }

        #endregion

        #region 服务过程监听

        protected virtual void OnStarted() { }

        protected virtual void OnStopped() { }

        protected virtual void OnConnected(SslSession session) { }

        protected virtual void OnHandshaked(SslSession session) { }

        protected virtual void OnDisconnected(SslSession session) { }

        protected virtual void OnError(SocketError error) { }

        internal void OnConnectedInternal(SslSession session) { OnConnected(session); }
        internal void OnHandshakedInternal(SslSession session) { OnHandshaked(session); }
        internal void OnDisconnectedInternal(SslSession session) { OnDisconnected(session); }

        #endregion

        #region 异常处理

        private void SendError(SocketError error)
        {
            // Skip disconnect errors
            if ((error == SocketError.ConnectionAborted) ||
                (error == SocketError.ConnectionRefused) ||
                (error == SocketError.ConnectionReset) ||
                (error == SocketError.OperationAborted) ||
                (error == SocketError.Shutdown))
                return;

            OnError(error);
        }

        #endregion

        #region 释放资源

        public bool IsDisposed { get; private set; }

        /// <summary>
        /// Acceptor socket disposed flag
        /// </summary>
        public bool IsSocketDisposed { get; private set; } = true;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposingManagedResources)
        {
            if (!IsDisposed)
            {
                if (disposingManagedResources)
                {
                    Stop();
                }

                IsDisposed = true;
            }
        }

        ~SslBaseServer()
        {
            Dispose(false);
        }

        #endregion
    }
}

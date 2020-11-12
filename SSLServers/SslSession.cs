using log4net;
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SSLServers
{
    /// <summary>
    /// 连接到服务端的客户端对象
    /// </summary>
    public class SslSession : IDisposable
    {
        private readonly static ILog _log = LogManager.GetLogger(typeof(SslSession));

        /// <summary>
        /// 初始化客户端对象信息
        /// </summary>
        /// <param name="server"></param>
        public SslSession(SslBaseServer server)
        {
            Id = Guid.NewGuid();
            Server = server;
            OptionReceiveBufferSize = server.OptionReceiveBufferSize;
            OptionSendBufferSize = server.OptionSendBufferSize;
        }

        public Guid Id { get; }

        public SslBaseServer Server { get; }

        public Socket Socket { get; private set; }

        public long BytesPending { get; private set; }

        public long BytesSending { get; private set; }

        public long BytesSent { get; private set; }

        public long BytesReceived { get; private set; }

        public int OptionReceiveBufferSize { get; set; } = 8192;

        public int OptionSendBufferSize { get; set; } = 8192;

        #region Connect/Disconnect session

        private bool _disconnecting;
        private SslStream _sslStream;
        private Guid? _sslStreamId;

        /// <summary>
        /// 是否已连接
        /// </summary>
        public bool IsConnected { get; private set; }

        /// <summary>
        /// 是否握手成功
        /// </summary>
        public bool IsHandshaked { get; private set; }

        /// <summary>
        /// 与客户端保持连接
        /// </summary>
        /// <param name="socket"></param>
        internal void Connect(Socket socket)
        {
            Socket = socket;

            IsSocketDisposed = false;

            _receiveBuffer = new Buffer();
            _sendBufferMain = new Buffer();
            _sendBufferFlush = new Buffer();

            if (Server.OptionKeepAlive)
                Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            if (Server.OptionNoDelay)
                Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

            _receiveBuffer.Reserve(OptionReceiveBufferSize);
            _sendBufferMain.Reserve(OptionSendBufferSize);
            _sendBufferFlush.Reserve(OptionSendBufferSize);

            BytesPending = 0;
            BytesSending = 0;
            BytesSent = 0;
            BytesReceived = 0;

            IsConnected = true;

            OnConnected();

            Server.OnConnectedInternal(this);

            try
            {
                _sslStreamId = Guid.NewGuid();
                _sslStream = (Server.Context.CertificateValidationCallback != null) ?
                    new SslStream(new NetworkStream(Socket, false), false, Server.Context.CertificateValidationCallback) :
                    new SslStream(new NetworkStream(Socket, false), false);

                _sslStream.BeginAuthenticateAsServer(Server.Context.Certificate, Server.Context.ClientCertificateRequired, Server.Context.Protocols, false, ProcessHandshake, _sslStreamId);
            }
            catch (Exception e)
            {
                _log.Error("Connect：" + e.ToString());
                SendError(SocketError.NotConnected);
                Disconnect();
            }
        }

        /// <summary>
        /// 与客户端断开连接
        /// </summary>
        /// <returns></returns>
        public virtual bool Disconnect()
        {
            if (!IsConnected)
                return false;

            if (_disconnecting)
                return false;

            _disconnecting = true;

            try
            {
                try
                {
                    _sslStream.ShutdownAsync().Wait();
                }
                catch (Exception) { }

                _sslStream.Dispose();
                _sslStreamId = null;

                try
                {
                    Socket.Shutdown(SocketShutdown.Both);
                }
                catch (SocketException) { }

                Socket.Close();

                Socket.Dispose();

                IsSocketDisposed = true;
            }
            catch (ObjectDisposedException) { }

            IsHandshaked = false;

            IsConnected = false;

            _receiving = false;
            _sending = false;

            ClearBuffers();

            OnDisconnected();

            Server.OnDisconnectedInternal(this);

            Server.UnregisterSession(Id);

            _disconnecting = false;

            return true;
        }

        #endregion

        #region 收发消息的数据体

        private bool _receiving;
        private Buffer _receiveBuffer;

        private readonly object _sendLock = new object();
        private bool _sending;
        private Buffer _sendBufferMain;
        private Buffer _sendBufferFlush;
        private long _sendBufferFlushOffset;

        /// <summary>
        /// 向客户端发送消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual long Send(byte[] buffer) { return Send(buffer, 0, buffer.Length); }

        /// <summary>
        /// 向客户端发送消息
        /// </summary>
        /// <param name="buffer">消息内容</param>
        /// <param name="offset">字节偏移量</param>
        /// <param name="size">字节大小</param>
        /// <returns></returns>
        public virtual long Send(byte[] buffer, long offset, long size)
        {
            if (!IsHandshaked)
                return 0;

            if (size == 0)
                return 0;

            try
            {
                // 先将内容写入到sslstream中进行加密
                _sslStream.Write(buffer, (int)offset, (int)size);

                BytesSent += size;//更新发送字节大小
                Interlocked.Add(ref Server._bytesSent, size);//多线程原子操作的变量

                return size;
            }
            catch (Exception)
            {
                SendError(SocketError.OperationAborted);
                Disconnect();
                return 0;
            }
        }

        /// <summary>
        /// 同步发送消息至客户端
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public virtual long Send(string text) { return Send(Encoding.UTF8.GetBytes(text)); }

        /// <summary>
        /// 同步发送消息至客户端
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual bool SendAsync(byte[] buffer) { return SendAsync(buffer, 0, buffer.Length); }

        /// <summary>
        /// 异步发送消息至客户端
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public virtual bool SendAsync(byte[] buffer, long offset, long size)
        {
            if (!IsHandshaked)
                return false;

            if (size == 0)
                return true;

            lock (_sendLock)
            {
                bool sendRequired = _sendBufferMain.IsEmpty || _sendBufferFlush.IsEmpty;

                _sendBufferMain.Append(buffer, offset, size);

                BytesPending = _sendBufferMain.Size;

                if (!sendRequired)
                    return true;
            }

            Task.Factory.StartNew(TrySend);

            return true;
        }

        /// <summary>
        /// 同步发送消息至客户端
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public virtual bool SendAsync(string text) { return SendAsync(Encoding.UTF8.GetBytes(text)); }

        /// <summary>
        /// 从客户端接收消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual long Receive(byte[] buffer) { return Receive(buffer, 0, buffer.Length); }

        /// <summary>
        /// 从客户端接收消息
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public virtual long Receive(byte[] buffer, long offset, long size)
        {
            if (!IsHandshaked)
                return 0;

            if (size == 0)
                return 0;

            try
            {
                long received = _sslStream.Read(buffer, (int)offset, (int)size);
                if (received > 0)
                {
                    BytesReceived += received;
                    Interlocked.Add(ref Server._bytesReceived, received);

                    OnReceived(buffer, 0, received);
                }

                return received;
            }
            catch (Exception)
            {
                SendError(SocketError.OperationAborted);
                Disconnect();
                return 0;
            }
        }

        /// <summary>
        /// 同步接收客户端消息
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public virtual string Receive(long size)
        {
            var buffer = new byte[size];
            var length = Receive(buffer);
            return Encoding.UTF8.GetString(buffer, 0, (int)length);
        }

        /// <summary>
        /// 异步接收客户端消息
        /// </summary>
        public virtual void ReceiveAsync()
        {
            TryReceive();
        }

        /// <summary>
        /// 尝试接收新的数据
        /// </summary>
        private void TryReceive()
        {
            if (_receiving)
                return;

            if (!IsHandshaked)
                return;

            try
            {
                IAsyncResult result;
                do
                {
                    if (!IsHandshaked)
                        return;

                    _receiving = true;
                    result = _sslStream.BeginRead(_receiveBuffer.Data, 0, (int)_receiveBuffer.Capacity, ProcessReceive, _sslStreamId);
                } while (result.CompletedSynchronously);
            }
            catch (ObjectDisposedException) { }
        }

        /// <summary>
        /// 尝试发送新的数据
        /// </summary>
        private void TrySend()
        {
            if (_sending)
                return;

            if (!IsHandshaked)
                return;

            lock (_sendLock)
            {
                if (_sending)
                    return;

                if (_sendBufferFlush.IsEmpty)
                {
                    lock (_sendLock)
                    {
                        _sendBufferFlush = Interlocked.Exchange(ref _sendBufferMain, _sendBufferFlush);
                        _sendBufferFlushOffset = 0;

                        BytesPending = 0;
                        BytesSending += _sendBufferFlush.Size;

                        _sending = !_sendBufferFlush.IsEmpty;
                    }
                }
                else
                    return;
            }

            if (_sendBufferFlush.IsEmpty)
            {
                OnEmpty();
                return;
            }

            try
            {
                _sslStream.BeginWrite(_sendBufferFlush.Data, (int)_sendBufferFlushOffset, (int)(_sendBufferFlush.Size - _sendBufferFlushOffset), ProcessSend, _sslStreamId);
            }
            catch (ObjectDisposedException) { }
        }

        private void ClearBuffers()
        {
            lock (_sendLock)
            {
                _sendBufferMain.Clear();
                _sendBufferFlush.Clear();
                _sendBufferFlushOffset = 0;

                BytesPending = 0;
                BytesSending = 0;
            }
        }

        #endregion

        #region IO processing

        /// <summary>
        /// 验证服务端和客户端是否通信成功
        /// </summary>
        private void ProcessHandshake(IAsyncResult result)
        {
            try
            {
                if (IsHandshaked)
                    return;

                var sslStreamId = result.AsyncState as Guid?;
                if (_sslStreamId != sslStreamId)
                    return;

                _sslStream.EndAuthenticateAsServer(result);

                IsHandshaked = true;

                OnHandshaked();

                Server.OnHandshakedInternal(this);

                if (_sendBufferMain.IsEmpty)
                    OnEmpty();

                TryReceive();
            }
            catch (Exception e)
            {
                _log.Error("ProcessHandshake：" + e.ToString());
                SendError(SocketError.NotConnected);
                Disconnect();
            }
        }

        private void ProcessReceive(IAsyncResult result)
        {
            try
            {
                if (!IsHandshaked)
                    return;

                var sslStreamId = result.AsyncState as Guid?;
                if (_sslStreamId != sslStreamId)
                    return;

                long size = _sslStream.EndRead(result);

                if (size > 0)
                {
                    BytesReceived += size;
                    Interlocked.Add(ref Server._bytesReceived, size);

                    OnReceived(_receiveBuffer.Data, 0, size);

                    if (_receiveBuffer.Capacity == size)
                        _receiveBuffer.Reserve(2 * size);
                }

                _receiving = false;

                if (size > 0)
                {
                    if (!result.CompletedSynchronously)
                        TryReceive();
                }
                else
                    Disconnect();
            }
            catch (Exception)
            {
                SendError(SocketError.OperationAborted);
                Disconnect();
            }
        }

        private void ProcessSend(IAsyncResult result)
        {
            try
            {
                var sslStreamId = result.AsyncState as Guid?;
                if (_sslStreamId != sslStreamId)
                    return;

                if (!IsHandshaked)
                    return;

                _sslStream.EndWrite(result);

                long size = _sendBufferFlush.Size;

                if (size > 0)
                {
                    BytesSending -= size;
                    BytesSent += size;
                    Interlocked.Add(ref Server._bytesSent, size);

                    _sendBufferFlushOffset += size;

                    if (_sendBufferFlushOffset == _sendBufferFlush.Size)
                    {
                        _sendBufferFlush.Clear();
                        _sendBufferFlushOffset = 0;
                    }
                }

                _sending = false;

                TrySend();
            }
            catch (Exception)
            {
                SendError(SocketError.OperationAborted);
                Disconnect();
            }
        }

        #endregion

        #region 客户端处理方法

        /// <summary>
        /// 客户端与服务端连接成功
        /// </summary>
        protected virtual void OnConnected() { }

        /// <summary>
        /// 客户端与服务端握手成功
        /// </summary>
        protected virtual void OnHandshaked() { }

        /// <summary>
        /// 客户端与服务端断开链接
        /// </summary>
        protected virtual void OnDisconnected() { }

        protected virtual void OnReceived(byte[] buffer, long offset, long size) { }

        protected virtual void OnEmpty() { }

        protected virtual void OnError(SocketError error) { }

        #endregion

        #region 异常处理

        private void SendError(SocketError error)
        {
            if ((error == SocketError.ConnectionAborted) ||
                (error == SocketError.ConnectionRefused) ||
                (error == SocketError.ConnectionReset) ||
                (error == SocketError.OperationAborted) ||
                (error == SocketError.Shutdown))
                return;

            OnError(error);
        }

        #endregion

        #region 释放连接对象

        public bool IsDisposed { get; private set; }

        /// <summary>
        /// 该socket连接对象是否已被释放
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
                    Disconnect();
                }

                IsDisposed = true;
            }
        }

        ~SslSession()
        {
            Dispose(false);
        }

        #endregion
    }
}

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SSLServers
{
    /// <summary>
    /// SSL 上下文
    /// </summary>
    public class SslContext
    {
        public SslContext() : this(SslProtocols.Tls12) { }

        public SslContext(SslProtocols protocols) { Protocols = protocols; }

        public SslContext(SslProtocols protocols, X509Certificate certificate) : this(protocols, certificate, null) { }

        public SslContext(SslProtocols protocols, X509Certificate certificate, RemoteCertificateValidationCallback certificateValidationCallback)
        {
            Protocols = protocols;
            Certificate = certificate;
            CertificateValidationCallback = certificateValidationCallback;
        }

        public SslContext(SslProtocols protocols, X509Certificate2Collection certificates) : this(protocols, certificates, null) { }

        public SslContext(SslProtocols protocols, X509Certificate2Collection certificates, RemoteCertificateValidationCallback certificateValidationCallback)
        {
            Protocols = protocols;
            Certificates = certificates;
            CertificateValidationCallback = certificateValidationCallback;
        }

        /// <summary>
        /// SSL protocols
        /// </summary>
        public SslProtocols Protocols { get; set; }

        /// <summary>
        /// SSL certificate
        /// </summary>
        public X509Certificate Certificate { get; set; }

        public X509Certificate2Collection Certificates { get; set; }

        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }

        public bool ClientCertificateRequired { get; set; }
    }
}

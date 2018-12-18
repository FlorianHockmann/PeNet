using System;
using System.Linq;
#if NETSTANDARD2_0
using System.Runtime.InteropServices;
#endif
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PeNet.Asn1;
using PeNet.Utilities;

namespace PeNet.Authenticode

    // References:
    // a.	http://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
{
    public class AuthenticodeInfo
    {
        private readonly PeFile _peFile;
        private readonly ContentInfo _contentInfo;

        public string SignerSerialNumber { get; }
        public byte[] SignedHash { get; }
        public bool IsAuthenticodeValid { get; }
        public X509Certificate2 SigningCertificate { get; }

        public AuthenticodeInfo(PeFile peFile)
        {
            _peFile = peFile;
            _contentInfo = new ContentInfo(_peFile.WinCertificate.bCertificate);
            SignerSerialNumber = GetSigningSerialNumber();
            SignedHash = GetSignedHash();
            IsAuthenticodeValid = VerifySignature();
            SigningCertificate = GetSigningCertificate();
        }

        private X509Certificate2 GetSigningCertificate()
        {
            if (_peFile.WinCertificate?.wCertificateType !=
                (ushort) Constants.WinCertificateType.WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            {
                return null;
            }

            var pkcs7 = _peFile.WinCertificate.bCertificate;

            // Workaround since the X509Certificate2 class does not return
            // the signing certificate in the PKCS7 byte array but crashes on Linux 
            // when using .Net Core.
            // Under Windows with .Net Core the class works as intended.
            // See issue: https://github.com/dotnet/corefx/issues/25828

#if NETSTANDARD2_0
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? 
                new X509Certificate2(pkcs7) : GetSigningCertificateNonWindows(_peFile); 
#else
            return new X509Certificate2(pkcs7);
#endif
        }

        private X509Certificate2 GetSigningCertificateNonWindows(PeFile peFile)
        {
            var collection = new X509Certificate2Collection();
            collection.Import(peFile.WinCertificate.bCertificate);
            return collection.Cast<X509Certificate2>().FirstOrDefault(cert =>
                string.Equals(cert.SerialNumber, SignerSerialNumber, StringComparison.CurrentCultureIgnoreCase));
        }

        private bool VerifySignature()
        {
            var signedCms = new SignedCms();
            signedCms.Decode(_peFile.WinCertificate.bCertificate);
            try
            {
                signedCms.CheckSignature(true);
            }
            catch (Exception)
            {
                // the signature was not valid
                return false;
            }

            return true;
        }

        private byte[] GetSignedHash()
        {
            if (_contentInfo.ContentType != "1.2.840.113549.1.7.2") //1.2.840.113549.1.7.2 = OID for signedData
            {
                return null;
            }

            var sd = new SignedData(_contentInfo.Content);
            if (sd.ContentInfo.ContentType != "1.3.6.1.4.1.311.2.1.4") // 1.3.6.1.4.1.311.2.1.4 = OID for Microsoft Crypto
            {
                return null;
            }

            var spc = sd.ContentInfo.Content;
            var signedHash = (Asn1OctetString)spc.Nodes[0].Nodes[1].Nodes[1];
            return signedHash.Data;
        }

        private string GetSigningSerialNumber()
        {
            var asn1 = _contentInfo.Content;
            var x = (Asn1Integer)asn1.Nodes[0].Nodes[4].Nodes[0].Nodes[1].Nodes[1]; // ASN.1 Path to signer serial number: /1/0/4/0/1/1
            return x.Value.ToHexString().Substring(2).ToUpper();
        }
    }
}
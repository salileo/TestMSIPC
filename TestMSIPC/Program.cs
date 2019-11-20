using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using MSIPC = Microsoft.InformationProtectionAndControl;

namespace TestMSIPC
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = "https://c15462ea-6cb8-4d75-a85d-ef3be30176f1.rms.na.hostedrms.com/_wmcs/licensing";
            
            Init();

            Uri uri = new Uri(url, UriKind.Absolute);
            byte[] result = Encrypt(uri, string.Empty, "salil is great");
        }

        public static void Init()
        {
            MSIPC.SafeNativeMethods.IpcInitialize();
            MSIPC.SafeNativeMethods.IpcSetAPIMode(MSIPC.APIMode.Server);
        }

        public static byte[] Encrypt(Uri uri, string templateString, string data)
        {
            MSIPC.ConnectionInfo connectionInfo = new MSIPC.ConnectionInfo(uri, uri);

            object cred = GetOAuthContext(null);
            // object cred = GetCertData();

            Collection<MSIPC.TemplateInfo> templates = MSIPC.SafeNativeMethods.IpcGetTemplateList(
                connectionInfo,
                forceDownload: false,
                suppressUI: true,
                offline: false,
                hasUserConsent: true,
                parentWindow: null,
                cultureInfo: null,
                credentialType: cred);

            MSIPC.TemplateInfo templateToUse = templates[0];
            foreach (MSIPC.TemplateInfo info in templates)
            {
                if (info.TemplateId == templateString)
                {
                    templateToUse = info;
                    break;
                }
            }

            templateString = templateToUse.TemplateId;
            if (!string.IsNullOrEmpty(templateString))
            {
                MSIPC.SafeInformationProtectionKeyHandle keyHandle = null;
                byte[] license = MSIPC.SafeNativeMethods.IpcSerializeLicense(
                    templateString,
                    MSIPC.SerializeLicenseFlags.KeyNoPersist,
                    suppressUI: true,
                    offline: false,
                    hasUserConsent: true,
                    parentWindow: null,
                    keyHandle: out keyHandle,
                    credentialType: cred);

                using (MemoryStream outputStream = new MemoryStream())
                {
                    int blockSize = MSIPC.SafeNativeMethods.IpcGetKeyBlockSize(keyHandle);
                    byte[] bytes = Encoding.UTF8.GetBytes(data);

                    MSIPC.SafeNativeMethods.IpcEncrypt(keyHandle, 0, true, ref bytes);

                    byte[] lengthBytes = BitConverter.GetBytes(license.Length);
                    int length = 0;
                    while (length + lengthBytes.Length < 4)
                    {
                        outputStream.WriteByte(0);
                        length++;
                    }

                    outputStream.Write(lengthBytes, 0, lengthBytes.Length);
                    outputStream.Write(license, 0, license.Length);
                    outputStream.Write(bytes, 0, bytes.Length);

                    return outputStream.ToArray();
                }
            }

            return null;
        }

        [DllImport(@"GetCert.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetCert(string name);

        [DllImport(@"GetCert.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeCert(IntPtr cert);

        [DllImport("crypt32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenStore(uint storeProvider, int encodingType, IntPtr hcryptProv, uint flags, string pvPara);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(IntPtr hCertStore, uint dwCertEncodingType, uint dwFindFlags, uint dwFindType, [In, MarshalAs(UnmanagedType.LPWStr)]string pszFindString, IntPtr pPrevCertCntxt);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertFreeCertificateContext(IntPtr hCertStore);

        public static object GetCertData()
        {
            string subj = "ome.outlook.office-int.net";

            const uint CERT_STORE_PROV_SYSTEM = 10;
            const uint CERT_STORE_FLAGS = 0x0002c000; // CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
            const uint CERT_ENCODING_TYPE = 0x00010001; // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            const uint CERT_FIND_SUBJECT_STR = 0x00080007;

            IntPtr hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, IntPtr.Zero, CERT_STORE_FLAGS, "MY");
            if (hSysStore != IntPtr.Zero)
            {
                IntPtr hCertCntxt = CertFindCertificateInStore(
                    hSysStore,
                    CERT_ENCODING_TYPE,
                    0,
                    CERT_FIND_SUBJECT_STR,
                    subj,
                    IntPtr.Zero);

                if (hCertCntxt != IntPtr.Zero)
                {
                    return hCertCntxt;
                }
            }

            return null;
        }

        public static MSIPC.OAuth2CallbackContext GetOAuthContext(object context)
        {
            return new MSIPC.OAuth2CallbackContext(context, GetOauthTokenCallback);
        }

        public static MSIPC.SafeInformationProtectionTokenHandle GetOauthTokenCallback(object context, NameValueCollection authenticationSettings)
        {
            StringBuilder challengeStringBldr = new StringBuilder();
            challengeStringBldr.Append("bearer ");

            string serviceRequestUrl = null;
            for (int i = 0; i < authenticationSettings.Count; i++)
            {
                string name = authenticationSettings.GetKey(i);
                string value = authenticationSettings.Get(i);
                if (name == "request_url")
                {
                    serviceRequestUrl = value;
                }
                else if (name == "authorization")
                {
                    challengeStringBldr.AppendFormat("authorization_uri=\"{0}\" ", value);
                }
                else
                {
                    challengeStringBldr.AppendFormat("{0}=\"{1}\" ", name, value);
                }
            }

            string challengeString = challengeStringBldr.ToString();
            challengeString = challengeString.TrimEnd();

            if (serviceRequestUrl.IndexOf(Uri.SchemeDelimiter) == -1)
            {
                serviceRequestUrl = Uri.UriSchemeHttps + Uri.SchemeDelimiter + serviceRequestUrl;
            }

            Uri uri = new Uri(serviceRequestUrl, UriKind.Absolute);

            //TODO
            
            string authToken = string.Empty;
            return MSIPC.SafeNativeMethods.IpcCreateOAuth2Token(authToken);
        }
    }
}

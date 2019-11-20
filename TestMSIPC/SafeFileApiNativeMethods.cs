using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Windows.Forms;

namespace Microsoft.InformationProtectionAndControl
{
    /*
    *   IMPORTANT - PLEASE READ
    *  If this class is public IpHub will complain as it references this project and the names will clash. 
    *  //TODO This needs to be made public after IPHub start using this functions instead of the privately 
    *  defined wrappers. 
    *  Also Note, The public interop sample shipped has this class as public
    */
    public static class SafeFileApiNativeMethods
    {

        public static string IpcfEncryptFile(
            string inputFile,
            string templateId,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            Form parentWindow,
            SymmetricKeyCredential symmKey = null,
            string outputDirectory = null)
        {
            return IpcfEncryptFile(
                inputFile,
                templateId,
                flags,
                suppressUI,
                offline,
                hasUserConsent,
                IpcWindow.Create(parentWindow).Handle,
                symmKey,
                outputDirectory);
        }

        public static string IpcfEncryptFile(
            string inputFile,
            string templateId,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            IntPtr parentWindow,
            SymmetricKeyCredential symmKey = null,
            string outputDirectory = null)
        {
            int hr = 0;
            IntPtr encryptedFileName = IntPtr.Zero;
            string outputFileName = null;

            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow,
                    symmKey);

            IntPtr licenseInfoPtr = Marshal.StringToHGlobalUni(templateId);

            try
            {
                hr = UnsafeFileApiMethods.IpcfEncryptFile(
                    inputFile,
                    licenseInfoPtr,
                    (uint)EncryptLicenseInfoTypes.IPCF_EF_TEMPLATE_ID,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    outputDirectory,
                    out encryptedFileName);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                outputFileName = Marshal.PtrToStringUni(encryptedFileName);
                if (null == outputFileName || 0 == outputFileName.Length)
                {
                    outputFileName = inputFile;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(licenseInfoPtr);
                UnsafeFileApiMethods.IpcFreeMemory(encryptedFileName);
                SafeNativeMethods.ReleaseIpcPromptContext(ipcContext);
            }

            return outputFileName;
        }

        public static string IpcfEncryptFile(
            string inputFile,
            SafeInformationProtectionLicenseHandle licenseHandle,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            Form parentWindow,
            SymmetricKeyCredential symmKey,
            string outputDirectory = null)
        {
            return IpcfEncryptFile(
                inputFile,
                licenseHandle,
                flags,
                suppressUI,
                offline,
                hasUserConsent,
                IpcWindow.Create(parentWindow).Handle,
                symmKey,
                outputDirectory);
        }

        public static string IpcfEncryptFile(
            string inputFile,
            SafeInformationProtectionLicenseHandle licenseHandle,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            IntPtr parentWindow,
            SymmetricKeyCredential symmKey,
            string outputDirectory = null)
        {
            int hr = 0;
            IntPtr encryptedFileName = IntPtr.Zero;
            string outputFileName = null;

            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow,
                    symmKey);

            try
            {
                hr = UnsafeFileApiMethods.IpcfEncryptFile(
                    inputFile,
                    licenseHandle.Value,
                    (uint)EncryptLicenseInfoTypes.IPCF_EF_LICENSE_HANDLE,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    outputDirectory,
                    out encryptedFileName);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                outputFileName = Marshal.PtrToStringUni(encryptedFileName);
                if (null == outputFileName || 0 == outputFileName.Length)
                {
                    outputFileName = inputFile;
                }
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(encryptedFileName);
                SafeNativeMethods.ReleaseIpcPromptContext(ipcContext);
            }

            return outputFileName;
        }

        public static string IpcfEncryptFileStream(
           Stream inputStream,
           string inputFilePath,
           string templateId,
           EncryptFlags flags,
           bool suppressUI,
           bool offline,
           bool hasUserConsent,
           Form parentWindow,
           SymmetricKeyCredential symmKey,
           ref Stream outputStream)
        {
            return IpcfEncryptFileStream(
               inputStream,
               inputFilePath,
               templateId,
               flags,
               suppressUI,
               offline,
               hasUserConsent,
               IpcWindow.Create(parentWindow).Handle,
               symmKey,
               ref outputStream);
        }

        public static string IpcfEncryptFileStream(
           Stream inputStream,
           string inputFilePath,
           string templateId,
           EncryptFlags flags,
           bool suppressUI,
           bool offline,
           bool hasUserConsent,
           IntPtr parentWindow,
           SymmetricKeyCredential symmKey,
           ref Stream outputStream)
        {
            int hr = 0;
            IntPtr encryptedFileName = IntPtr.Zero;
            string outputFileName = null;
            ILockBytes ilInputStream = new ILockBytesOverStream(inputStream);
            ILockBytes ilOutputStream = new ILockBytesOverStream(outputStream);


            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow,
                    symmKey);

            IntPtr licenseInfoPtr = Marshal.StringToHGlobalUni(templateId);

            try
            {
                hr = UnsafeFileApiMethods.IpcfEncryptFileStream(
                    ilInputStream,
                    inputFilePath,
                    licenseInfoPtr,
                    (uint)EncryptLicenseInfoTypes.IPCF_EF_TEMPLATE_ID,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    ilOutputStream,
                    out encryptedFileName);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                outputFileName = Marshal.PtrToStringUni(encryptedFileName);
                if (null == outputFileName || 0 == outputFileName.Length)
                {
                    outputFileName = inputFilePath;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(licenseInfoPtr);
                UnsafeFileApiMethods.IpcFreeMemory(encryptedFileName);
            }

            return outputFileName;
        }


        public static string IpcfEncryptFileStream(
            Stream inputStream,
            string inputFilePath,
            SafeInformationProtectionLicenseHandle licenseHandle,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            Form parentWindow,
            SymmetricKeyCredential symmKey,
            ref Stream outputStream)
        {
            return IpcfEncryptFileStream(
                inputStream,
                inputFilePath,
                licenseHandle,
                flags,
                suppressUI,
                offline,
                hasUserConsent,
                IpcWindow.Create(parentWindow).Handle,
                symmKey,
                ref outputStream);
        }

        public static string IpcfEncryptFileStream(
            Stream inputStream,
            string inputFilePath,
            SafeInformationProtectionLicenseHandle licenseHandle,
            EncryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            IntPtr parentWindow,
            SymmetricKeyCredential symmKey,
            ref Stream outputStream)
        {
            int hr = 0;
            IntPtr encryptedFileName = IntPtr.Zero;
            string outputFileName = null;
            ILockBytes ilInputStream = new ILockBytesOverStream(inputStream);
            ILockBytes ilOutputStream = new ILockBytesOverStream(outputStream);

            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow,
                    symmKey);

            try
            {
                hr = UnsafeFileApiMethods.IpcfEncryptFileStream(
                    ilInputStream,
                    inputFilePath,
                    licenseHandle.Value,
                    (uint)EncryptLicenseInfoTypes.IPCF_EF_LICENSE_HANDLE,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    ilOutputStream,
                    out encryptedFileName);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                outputFileName = Marshal.PtrToStringUni(encryptedFileName);
                if (null == outputFileName || 0 == outputFileName.Length)
                {
                    outputFileName = inputFilePath;
                }
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(encryptedFileName);
            }

            return outputFileName;
        }


        public static string IpcfDecryptFile(
            string inputFile,
            DecryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            Form parentWindow,
            SymmetricKeyCredential symmKey,
            string outputDirectory = null)
        {
            return IpcfDecryptFile(
                inputFile,
                flags,
                suppressUI,
                offline,
                hasUserConsent,
                IpcWindow.Create(parentWindow).Handle,
                symmKey,
                outputDirectory);
        }

        public static string IpcfDecryptFile(
            string inputFile,
            DecryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            IntPtr parentWindow,
            SymmetricKeyCredential symmKey,
            string outputDirectory = null)
        {
            int hr = 0;
            IntPtr decryptedFileNamePtr = IntPtr.Zero;
            string decryptedFileName = null;

            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow,
                    symmKey);

            try
            {
                hr = UnsafeFileApiMethods.IpcfDecryptFile(
                    inputFile,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    outputDirectory,
                    out decryptedFileNamePtr);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                decryptedFileName = Marshal.PtrToStringUni(decryptedFileNamePtr);
                if (null == decryptedFileName || 0 == decryptedFileName.Length)
                {
                    decryptedFileName = inputFile;
                }
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(decryptedFileNamePtr);
                SafeNativeMethods.ReleaseIpcPromptContext(ipcContext);
            }

            return decryptedFileName;
        }

        public static string IpcfDecryptFileStream(
            Stream inputStream,
            string inputFilePath,
            DecryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            Form parentWindow,
            ref Stream outputStream)
        {
            return IpcfDecryptFileStream(
                inputStream,
                inputFilePath,
                flags,
                suppressUI,
                offline,
                hasUserConsent,
                IpcWindow.Create(parentWindow).Handle,
                ref outputStream);
        }

        public static string IpcfDecryptFileStream(
            Stream inputStream,
            string inputFilePath,
            DecryptFlags flags,
            bool suppressUI,
            bool offline,
            bool hasUserConsent,
            IntPtr parentWindow,
            ref Stream outputStream)
        {
            int hr = 0;
            IntPtr decryptedFileNamePtr = IntPtr.Zero;
            string decryptedFileName = null;
            ILockBytes ilInputStream = new ILockBytesOverStream(inputStream);
            ILockBytes ilOutputStream = new ILockBytesOverStream(outputStream);

            SafeIpcPromptContext ipcContext =
                SafeNativeMethods.CreateIpcPromptContext(suppressUI,
                    offline,
                    hasUserConsent,
                    parentWindow);

            try
            {
                hr = UnsafeFileApiMethods.IpcfDecryptFileStream(
                    ilInputStream,
                    inputFilePath,
                    (uint)flags,
                    (IpcPromptContext)ipcContext,
                    ilOutputStream,
                    out decryptedFileNamePtr);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                decryptedFileName = Marshal.PtrToStringUni(decryptedFileNamePtr);
                if (null == decryptedFileName || 0 == decryptedFileName.Length)
                {
                    decryptedFileName = inputFilePath;
                }
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(decryptedFileNamePtr);
            }

            return decryptedFileName;
        }

        public static byte[] IpcfGetSerializedLicenseFromFile(string inputFile)
        {
            byte[] license = null;
            int hr = 0;

            IntPtr licensePtr = IntPtr.Zero;
            try
            {
                hr = UnsafeFileApiMethods.IpcfGetSerializedLicenseFromFile(
                    inputFile,
                    out licensePtr);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                license = SafeNativeMethods.MarshalIpcBufferToManaged(licensePtr);
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(licensePtr);
            }
            return license;
        }

        public static byte[] IpcfGetSerializedLicenseFromFileStream(
            Stream inputStream,
            string inputFilePath)
        {
            byte[] license = null;
            int hr = 0;
            ILockBytes ilInputStream = new ILockBytesOverStream(inputStream);

            IntPtr licensePtr = IntPtr.Zero;
            try
            {
                hr = UnsafeFileApiMethods.IpcfGetSerializedLicenseFromFileStream(
                    ilInputStream,
                    inputFilePath,
                    out licensePtr);

                SafeNativeMethods.ThrowOnErrorCode(hr);

                license = SafeNativeMethods.MarshalIpcBufferToManaged(licensePtr);
            }
            finally
            {
                UnsafeFileApiMethods.IpcFreeMemory(licensePtr);
            }
            return license;
        }

        public static FileEncryptedStatus IpcfIsFileEncrypted(string inputFile)
        {
            uint fileStatus;
            int hr = UnsafeFileApiMethods.IpcfIsFileEncrypted(inputFile, out fileStatus);
            SafeNativeMethods.ThrowOnErrorCode(hr);

            return (FileEncryptedStatus)fileStatus;

        }

        public static bool IpcfIsFileStreamEncrypted(Stream inputStream, string inputFilePath)
        {
            uint fileStatus;
            ILockBytes ilInputStream = new ILockBytesOverStream(inputStream);
            int hr = UnsafeFileApiMethods.IpcfIsFileStreamEncrypted(ilInputStream, inputFilePath, out fileStatus);
            SafeNativeMethods.ThrowOnErrorCode(hr);

            return (FileEncryptedStatus)fileStatus != FileEncryptedStatus.IPCF_FILE_STATUS_DECRYPTED;
        }

        public enum FileEncryptedStatus
        {
            IPCF_FILE_STATUS_DECRYPTED                              = 0,
            IPCF_FILE_STATUS_ENCRYPTED_CUSTOM                       = 1,
            IPCF_FILE_STATUS_ENCRYPTED                              = 2
        }

        public enum EncryptLicenseInfoTypes
        {
            IPCF_EF_TEMPLATE_ID                                     = 0,
            IPCF_EF_LICENSE_HANDLE                                  = 1
        }

        [Flags]
        public enum EncryptFlags
        {
            IPCF_EF_FLAG_DEFAULT                                     = 0x00000000,
            IPCF_EF_FLAG_UPDATELICENSE_BLOCKED                       = 0x00000001,
            IPCF_EF_FLAG_KEY_NO_PERSIST                              = 0x00000002,
            IPCF_EF_FLAG_KEY_NO_PERSIST_DISK                         = 0x00000004,
            IPCF_EF_FLAG_KEY_NO_PERSIST_LICENSE                      = 0x00000008
        }

        [Flags]
        public enum DecryptFlags
        {
            IPCF_DF_FLAG_DEFAULT            = 0x00000000,
            IPCF_DF_FLAG_OPEN_AS_RMS_AWARE =  0x00000001
        }
    }
}

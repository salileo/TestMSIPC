//-----------------------------------------------------------------------------
//
// <copyright file="NativeAPIStructures.cs" company="Microsoft">
//    Copyright (C) Microsoft Corporation.  All rights reserved.
// </copyright>
//
// Description:  Structure declarations for interop services required to call into unmanaged IPC SDK APIs   
//
//
//-----------------------------------------------------------------------------

using System;
using System.IO;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.InformationProtectionAndControl
{
    // Environment Property types - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535247(v=vs.85).aspx
    public enum EnvironmentInformationType : uint
    {
        SecurityMode = 3,
        ApplicationId = 5,
    };

    // Prompt Context flags - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535278(v=vs.85).aspx
    public enum PromptContextFlag : uint
    {
        Slient = 1,
        Offline = 2,
        HasUserConsent = 4,
        AcsCredential = 0x20000000,
    };

    // IpcSerializeLicense() function input types - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535269(v=vs.85).aspx
    public enum SerializationInputType : uint
    {
        TemplateId = 1,
        License = 2,
    }

    // IpcGetTemplateList() function flags - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535267(v=vs.85).aspx
    public enum GetTemplateListFlags : uint
    {
        ForceDownload = 1
    }

    // IpcGetTemplateIssuerList() function flags - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535266(v=vs.85).aspx
    public enum GetTemplateIssuerListFlags : uint
    {
        DefaultServerOnly = 1
    }

    // License Property types - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535287(v=vs.85).aspx
    public enum LicensePropertyType : uint
    {
        ValidityTime = 1,
        IntervalTime = 2,
        Owner = 3,
        UserRightsList = 4,
        AppSpecificData = 5,
        DeprecatedEncryptionAlgorithms = 6,
        ConnectionInfo = 7,
        Descriptor = 8,
        ReferralInfoUrl = 10,
        ContentKey = 11,
        ContentId = 12,
        AppSpecificDataNoEncryption = 13,
    };

    // Key Property types - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535264(v=vs.85).aspx
    public enum KeyPropertyType : uint
    {
        BlockSize = 2,
        License = 6,
        UserDisplayName = 7,
    };

    public enum IpcCredentialType : uint
    {
        X509Certificate = 1,
        SymmetricKey = 2,
        OAuth2 = 3,
    }

    //
    [StructLayout(LayoutKind.Sequential)]
    public class IpcApplicationId
    {
        private readonly uint cbSize;

        [MarshalAs(UnmanagedType.LPWStr)]
        private readonly string wszClientId;

        [MarshalAs(UnmanagedType.LPWStr)]
        private readonly string wszRedirectUri;

        public IpcApplicationId(string clientId, string redirectUri)
        {
            this.cbSize = (uint)Marshal.SizeOf(typeof(IpcApplicationId));
            wszClientId = clientId;
            wszRedirectUri = redirectUri;
        }

        string ClientId
        {
            get
            {
                return wszClientId;
            }
        }

        string RedirectUri
        {
            get
            { 
                return wszRedirectUri;
            }
        }
    }

    //IPC_AUTHENTICATION_CALLBACK_INFO
    [StructLayout(LayoutKind.Sequential)]
    public class IpcOAuth2CallbackInfo
    {
        public delegate int IpcOAuth2Delegate(IntPtr context, IntPtr authenticationParameters, out IntPtr iph);
        private uint cbSize;
        private IpcOAuth2Delegate pfnGetToken;
        private IntPtr pvContext;

        public IpcOAuth2CallbackInfo(IpcOAuth2Delegate callback, IntPtr context)
        {
            this.cbSize = (uint)Marshal.SizeOf(typeof(IpcOAuth2CallbackInfo));
            pfnGetToken = callback;
            pvContext = context;
        }
    }

    //IPC_CREDENTIAL http://msdn.microsoft.com/en-us/library/windows/desktop/hh535275(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    internal class IpcCredential
    {
        private IpcCredentialType type;

        //union of certificateContext | symmetricKey
        private IntPtr credData;

        public IpcCredential() : this(IpcCredentialType.SymmetricKey, null) { }
        public IpcCredential(IpcCredentialType typeIn, object credDataIn)
        {
            type = typeIn;
            credData = IntPtr.Zero;
            if (null != credDataIn)
            {
                switch (type)
                {
                    case IpcCredentialType.SymmetricKey:
                        SymmetricKeyCredential symmKey = (SymmetricKeyCredential)credDataIn;
                        credData = Marshal.AllocHGlobal(Marshal.SizeOf(symmKey));
                        Marshal.StructureToPtr(symmKey, credData, false);
                        break;
                    case IpcCredentialType.OAuth2:
                        IpcOAuth2CallbackInfo oath2Key = (IpcOAuth2CallbackInfo)credDataIn;
                        credData = Marshal.AllocHGlobal(Marshal.SizeOf(oath2Key));
                        Marshal.StructureToPtr(oath2Key, credData, false);
                        break;
                    case IpcCredentialType.X509Certificate:
                        IntPtr certificateData = (IntPtr)credDataIn;
                        credData = certificateData;
                        break;
                    default:
                        credData = IntPtr.Zero;
                        throw new NotImplementedException();
                }
            }
        }

        internal void Dispose()
        {
            if (IntPtr.Zero != credData)
            {
                IntPtr credDataLocal = credData;
                credData = IntPtr.Zero;

                if (type != IpcCredentialType.X509Certificate)
                {
                    Marshal.FreeHGlobal(credDataLocal);
                }
            }
        }
    }
    
    //IPC_CREDENTIAL_SYMMETRIC_KEY http://msdn.microsoft.com/en-us/library/windows/desktop/dn133062(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class SymmetricKeyCredential
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Base64Key;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string AppPrincipalId;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string BposTenantId;
    }

    public delegate SafeInformationProtectionTokenHandle GetAuthenticationTokenDelegate(Object context,
        NameValueCollection authenticationSettings);

    public sealed class OAuth2CallbackContext : SafeHandle
    {
        private readonly GCHandle callbackContext;
        private readonly GCHandle callback;
        private readonly GCHandle thisObj;

        public OAuth2CallbackContext(Object callbackContext, GetAuthenticationTokenDelegate callback) :
            base(IntPtr.Zero, true)
        {
            this.callbackContext = GCHandle.Alloc(callbackContext);
            this.callback = GCHandle.Alloc(callback);
            thisObj = GCHandle.Alloc(this);
            SetHandle(GCHandle.ToIntPtr(thisObj));
        }

        internal IntPtr Context
        {
            get
            {
                return handle;
            }
        }

        public Object CallbackContext
        {
            get
            {
                Object result = null;
                if (callbackContext.IsAllocated)
                {
                    result = callbackContext.Target;
                }
                return result;
            }
        }

        public GetAuthenticationTokenDelegate Callback
        {
            get
            {
                GetAuthenticationTokenDelegate result = null;
                if (callback.IsAllocated)
                {
                    result = (GetAuthenticationTokenDelegate)callback.Target;
                }
                return result;
            }
        }

        private class ExceptionTranslator : Exception
        {
            public ExceptionTranslator(Exception except)
                : base(except.Message, except)
            {
            }

            public int HR
            {
                get
                {
                    return HResult;
                }
            }
        }

        private static int GetAuthenticationTokenCallback(IntPtr context, IntPtr authenticationParameters, out IntPtr iph)
        {
            int result = 0;
            OAuth2CallbackContext authCallbackContext = null;
            iph = IntPtr.Zero;
            try
            {
                GCHandle gch = GCHandle.FromIntPtr(context);
                authCallbackContext = (OAuth2CallbackContext)gch.Target;

                NameValueCollection authParamList = new NameValueCollection();
                SafeNativeMethods.MarshalNameValueListToManaged(authenticationParameters, authParamList);

                if (null != authCallbackContext.Callback)
                {
                    SafeInformationProtectionTokenHandle safeToken =
                        authCallbackContext.Callback(authCallbackContext.CallbackContext, authParamList);
                    IntPtr iphValue = safeToken.Value;
                    safeToken.SetHandleAsInvalid();
                    iph = iphValue;
                }
            }
            catch (Exception except)
            {
                result = (new ExceptionTranslator(except)).HR;
            }
            return result;
        }

        internal IpcOAuth2CallbackInfo.IpcOAuth2Delegate MarshallingCallback
        {
            get
            {
                IpcOAuth2CallbackInfo.IpcOAuth2Delegate callback = null;
                if (null != Callback)
                {
                    callback = GetAuthenticationTokenCallback;
                }
                return callback;
            }
        }

        public override bool IsInvalid
        {
            get { return this.handle.Equals(IntPtr.Zero); }
        }

        protected override bool ReleaseHandle()
        {
            if (callback.IsAllocated)
            {
                callback.Free();
            }
            if (callbackContext.IsAllocated)
            {
                callbackContext.Free();
            }
            if (thisObj.IsAllocated)
            {
                thisObj.Free();
            }
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    public class SafeIpcPromptContext : IDisposable
    {
        private IpcPromptContext internalClass;

        internal SafeIpcPromptContext(IntPtr wndParent, IpcCredential credential, IntPtr cancelEvent)
        {
            internalClass = new IpcPromptContext(wndParent, credential, cancelEvent);
        }

        ~SafeIpcPromptContext()
        {
            try
            {
                Dispose();
            }
            catch (Exception)
            {
            }
        }

        public void Dispose()
        {
            if (null != internalClass)
            {
                internalClass.Dispose();
            }
        }

        public static explicit operator IpcPromptContext(SafeIpcPromptContext obj)
        {
            return obj.internalClass;
        }
    }

    // IPC_PROMPT_CONTEXT - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535278(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcPromptContext
    {
        public uint cbSize;
        public readonly IntPtr hWndParent;
        public uint flags;
        public readonly IntPtr hCancelEvent;
        private IntPtr pcCredential;

        internal IpcPromptContext()
        {
            this.cbSize = (uint)Marshal.SizeOf(typeof(IpcPromptContext));
            flags = 0;
        }

        internal IpcPromptContext(IntPtr wndParent, IpcCredential credential, IntPtr cancelEvent)
            : this()
        {
            hWndParent = wndParent;
            hCancelEvent = cancelEvent;
            if (null != credential)
            {
                pcCredential = Marshal.AllocHGlobal(Marshal.SizeOf(credential));
                Marshal.StructureToPtr(credential, pcCredential, false);
            }
            else
            {
                pcCredential = IntPtr.Zero;
            }
        }

        internal void Dispose()
        {
            if (IntPtr.Zero != pcCredential)
            {
                IpcCredential cred = new IpcCredential();
                Marshal.PtrToStructure(pcCredential, cred);
                pcCredential = IntPtr.Zero;
                cred.Dispose();
            }
        }
    }

    // IPC_TEMPLATE_INFO - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535279(v=vs.85).aspx
    [StructLayout( LayoutKind.Sequential, CharSet=CharSet.Unicode )]
    public class IpcTemplateInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string templateID;
        public uint lcid;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string templateName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string templateDescription;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string issuerDisplayName;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fromTemplate;
    }

    // IPC_TEMPLATE_ISSUER - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535280(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class IpcTemplateIssuer
    {
        public IpcConnectionInfo connectionInfo;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string wszDisplayName;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAllowFromScratch;

    }

    // IPC_USER - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535284(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcUser 
    {
        [MarshalAs(UnmanagedType.U4)]
        public UserIdType userType;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string userID;
    }

    // IPC_TERM - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535282(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcTerm 
    {
        public FileTime ftStart;
        public ulong dwDuration;
    }

    // IPC_NAME_VALUE - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535276(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcNameValue
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Name;
        public uint lcid;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Value;
    }

    // IPC_USER_RIGHTS - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535285(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcUserRights
    {
        public IpcUser user;
        private uint cRights;
        private IntPtr rgwszRights;

        public IpcUserRights() { }
        public IpcUserRights(UserRights userRights)
            : this()
        {
            user = new IpcUser();
            user.userType = userRights.UserIdType;
            user.userID = userRights.UserId;
            cRights = (uint)userRights.Rights.Count;

            // Allocate memory for the right string array
            rgwszRights = Marshal.AllocHGlobal(userRights.Rights.Count * Marshal.SizeOf(typeof(IntPtr)));

            // go to the first right string entry
            IntPtr currentRightPtr = rgwszRights;

            foreach (string right in userRights.Rights)
            {
                // the right string itself
                IntPtr RightStringPtr = Marshal.StringToHGlobalUni(right);

                // assign the pointer
                Marshal.WriteIntPtr(currentRightPtr, 0, RightStringPtr);

                // go to the next right string entry
                currentRightPtr = new IntPtr(currentRightPtr.ToInt64() + Marshal.SizeOf(typeof(IntPtr)));
            }
        }

        internal void Dispose()
        {
            if (IntPtr.Zero != rgwszRights)
            {
                IntPtr rights = rgwszRights;
                int ctRights = (int)cRights;

                rgwszRights = IntPtr.Zero;
                cRights = 0;

                for (int idx = 0; idx < ctRights; idx++)
                {
                    // Get the j-th right from the ipcUserRights.rgwszRights string array
                    IntPtr RightStringPtr = Marshal.ReadIntPtr(rights, idx * Marshal.SizeOf(typeof(IntPtr)));

                    Marshal.FreeHGlobal(RightStringPtr);
                }
                Marshal.FreeHGlobal(rights);
            }
        }

        public UserRights MarshalUserRightsToManaged()
        {
            System.Collections.ObjectModel.Collection<string> rightList = new System.Collections.ObjectModel.Collection<string>();

            // go to the first right string entry
            IntPtr currentRightPtr = rgwszRights;
            for (int idx = 0; idx < (int)cRights; idx++)
            {
                // Get the j-th right from the ipcUserRights.rgwszRights string array
                IntPtr RightStringPtr = Marshal.ReadIntPtr(rgwszRights, idx * Marshal.SizeOf(typeof(IntPtr)));

                // Read the string
                string right = Marshal.PtrToStringUni(RightStringPtr);

                rightList.Add(right);
            }
            return new UserRights(user.userType, user.userID, rightList);
        }
    }

    // IPC_USER_RIGHTS_LIST (excluding the variable size array rgUserRights) - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535286(v=vs.85).aspx
    // In the native API, a USER_RIGHTS_LIST is a structure with the below fields, followed by a list of USER_RIGHTS
    // structs using the ANYSIZE_ARRAY pattern. This does not match any automatic marshal type, so we instead
    // automatically marshal only the below fields and manually marshal the array.
    [StructLayout(LayoutKind.Sequential)]
    public class IpcUserRightsList_Header
    {
        public uint cbSize;
        public uint cUserRights;
        //public UserRights[] rgUserRights; (variable size arrays are not supported by interop layer, see above)
    }

    public class SafeIpcBuffer : IDisposable
    {
        private IpcBuffer internalClass;

        public SafeIpcBuffer(byte[] buffer)
        {
            internalClass = new IpcBuffer(buffer);
        }

        ~SafeIpcBuffer()
        {
            try
            {
                Dispose();
            }
            catch (Exception)
            {
            }
        }

        public void Dispose()
        {
            if (null != internalClass)
            {
                internalClass.Dispose();
            }
        }

        public static explicit operator IpcBuffer(SafeIpcBuffer obj)
        {
            return obj.internalClass;
        }
    }

    // IPC_BUFFER - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535273(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcBuffer
    {
        private IntPtr pvBuffer;
        private uint cbBuffer;

        public IpcBuffer() : this(null) { }
        public IpcBuffer(byte[] buffer)
        {
            if (null != buffer && 0 != buffer.Length)
            {
                cbBuffer = (uint)buffer.Length;
                pvBuffer = Marshal.AllocHGlobal(buffer.Length);
                try
                {
                    Marshal.Copy(buffer, 0, pvBuffer, buffer.Length);
                }
                catch
                {
                    try
                    {
                        Dispose();
                    }
                    catch (Exception)
                    {
                    }
                    throw;
                }
            }
            else
            {
                pvBuffer = IntPtr.Zero;
                cbBuffer = 0;
            }
        }

        internal void Dispose()
        {
            if (IntPtr.Zero != pvBuffer)
            {
                IntPtr freeMem = pvBuffer;
                pvBuffer = IntPtr.Zero;
                Marshal.FreeHGlobal(freeMem);
            }
        }

        public byte[] ToArray()
        {
            byte[] buffer = new byte[cbBuffer];
            if (IntPtr.Zero != pvBuffer)
            {
                Marshal.Copy(pvBuffer, buffer, 0, (int)cbBuffer);
            }
            return buffer;
        }
    }

    // IPC_CONNECTION_INFO - http://msdn.microsoft.com/en-us/library/windows/desktop/hh535274(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public class IpcConnectionInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ExtranetUrl;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string IntranetUrl;
    }

    // FILETIME - http://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public struct FileTime
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;

        public FileTime(long fileTime)
        {
            byte[] bytes = BitConverter.GetBytes(fileTime);
            dwLowDateTime = BitConverter.ToUInt32(bytes, 0);
            dwHighDateTime = BitConverter.ToUInt32(bytes, 4);
        }

        public static implicit operator long(FileTime fileTime)
        {
            long returnedLong;
            byte[] highBytes = BitConverter.GetBytes(fileTime.dwHighDateTime);
            Array.Resize(ref highBytes, 8);
            returnedLong = BitConverter.ToInt64(highBytes, 0);
            returnedLong = returnedLong << 32;
            returnedLong = returnedLong | fileTime.dwLowDateTime;
            return returnedLong;
        }
    }

    public enum NotificationTypeEnabled
    {
        IPCD_CT_NOTIFICATION_TYPE_DISABLED = 0,
        IPCD_CT_NOTIFICATION_TYPE_ENABLED = 1
    }

    // IPC_LICENSE_METADATA
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public class IpcLicenseMetadata
    {
        [MarshalAs(UnmanagedType.U4)]
        public uint cbSize;

        [MarshalAs(UnmanagedType.U4)]
        public uint dwNotificationType;

        [MarshalAs(UnmanagedType.U4)]
        public uint dwNotificationPreference;

        [MarshalAs(UnmanagedType.U8)]
        public long ftDateModified;

        [MarshalAs(UnmanagedType.U8)]
        public long ftDateCreated;

        [MarshalAs(UnmanagedType.LPWStr)]
        public readonly string wszContentName;

        public IpcLicenseMetadata(string filePath, string contentName, bool notificationsEnabled, uint notificationPref = 0)
        {
            cbSize = (uint)Marshal.SizeOf(typeof(IpcLicenseMetadata));
            dwNotificationType = (notificationsEnabled) ? (uint)NotificationTypeEnabled.IPCD_CT_NOTIFICATION_TYPE_ENABLED
                                                        : (uint)NotificationTypeEnabled.IPCD_CT_NOTIFICATION_TYPE_DISABLED;
            dwNotificationPreference = notificationPref;
            ftDateModified = File.GetLastWriteTimeUtc(filePath).ToFileTimeUtc();
            ftDateCreated = File.GetCreationTimeUtc(filePath).ToFileTimeUtc();
            wszContentName = contentName;
        }
    }
}

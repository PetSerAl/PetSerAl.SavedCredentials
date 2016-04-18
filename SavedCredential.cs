using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
namespace PetSerAl.SavedCredentials {
    public sealed class SavedCredential {
        public static void Delete(string targetName) => Delete(targetName, SavedCredentialType.Generic);
        public static void Delete(string targetName, SavedCredentialType type) => Delete(targetName, type, SavedCredentialDeleteFlags.None);
        [SecuritySafeCritical, SavedCredentialPermission(SecurityAction.Demand, Unrestricted = true), SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
        public static void Delete(string targetName, SavedCredentialType type, SavedCredentialDeleteFlags flags) => NativeMethods.CredDelete(targetName, type, flags);
        public static SavedCredential[] Enumerate(string filter) => Enumerate(filter, SavedCredentialEnumerateFlags.None);
        [SecuritySafeCritical, SavedCredentialPermission(SecurityAction.Demand, Unrestricted = true), SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
        public static SavedCredential[] Enumerate(string filter, SavedCredentialEnumerateFlags flags) {
            IntPtr handle = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try {
                int count;
                NativeMethods.CredEnumerate(filter, flags, out count, out handle);
                SavedCredential[] credentials = new SavedCredential[count];
                for(int i = 0; i<count; ++i) {
                    credentials[i]=new SavedCredential(Marshal.ReadIntPtr(handle, IntPtr.Size*i));
                }
                return credentials;
            } finally {
                if(handle!=IntPtr.Zero) {
                    NativeMethods.CredFree(handle);
                }
            }
        }
        public static SavedCredential Read(string targetName) => Read(targetName, SavedCredentialType.Generic);
        public static SavedCredential Read(string targetName, SavedCredentialType type) => Read(targetName, type, SavedCredentialReadFlags.None);
        [SecuritySafeCritical, SavedCredentialPermission(SecurityAction.Demand, Unrestricted = true), SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
        public static SavedCredential Read(string targetName, SavedCredentialType type, SavedCredentialReadFlags flags) {
            IntPtr handle = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try {
                NativeMethods.CredRead(targetName, type, flags, out handle);
                return new SavedCredential(handle);
            } finally {
                if(handle!=IntPtr.Zero) {
                    NativeMethods.CredFree(handle);
                }
            }
        }
        private readonly SavedCredentialNative credentialNative;
        private SecureString credentialBlob;
        [SecurityCritical]
        private SavedCredential(IntPtr handle) {
            credentialNative=(SavedCredentialNative)Marshal.PtrToStructure(handle, typeof(SavedCredentialNative));
            credentialBlob=new SecureString();
            PostReadFixup();
        }
        public SavedCredential(string targetName) : this(targetName, SavedCredentialType.Generic) { }
        public SavedCredential(string targetName, SavedCredentialType type) {
            credentialNative=new SavedCredentialNative {
                Type=type,
                TargetName=targetName??string.Empty,
                TargetAlias=string.Empty,
                UserName=string.Empty,
                Persist=SavedCredentialPersist.Session,
                Comment=string.Empty
            };
            credentialBlob=new SecureString();
        }
        public SavedCredentialType Type {
            get {
                lock(credentialNative) {
                    return credentialNative.Type;
                }
            }
        }
        public string TargetName {
            get {
                lock(credentialNative) {
                    return credentialNative.TargetName;
                }
            }
        }
        public string TargetAlias {
            get {
                lock(credentialNative) {
                    return credentialNative.TargetAlias;
                }
            }
            set {
                lock(credentialNative) {
                    credentialNative.TargetAlias=value??string.Empty;
                }
            }
        }
        public string UserName {
            get {
                lock(credentialNative) {
                    return credentialNative.UserName;
                }
            }
            set {
                lock(credentialNative) {
                    credentialNative.UserName=value??string.Empty;
                }
            }
        }
        public int CredentialBlobSize {
            get {
                lock(credentialNative) {
                    return credentialNative.CredentialBlobSize;
                }
            }
        }
        public SecureString CredentialBlob {
            get {
                lock(credentialNative) {
                    if(credentialNative.CredentialBlobSize%2!=0) {
                        throw new NotImplementedException();
                    }
                    return credentialBlob.Copy();
                }
            }
            set {
                SecureString copy = value?.Copy();
                lock(credentialNative) {
                    if(copy==null) {
                        credentialBlob.Clear();
                    }else {
                        credentialBlob.Dispose();
                        credentialBlob=copy;
                    }
                    credentialNative.CredentialBlobSize=credentialBlob.Length*2;
                }
            }
        }
        public SavedCredentialPersist Persist {
            get {
                lock(credentialNative) {
                    return credentialNative.Persist;
                }
            }
            set {
                lock(credentialNative) {
                    credentialNative.Persist=value;
                }
            }
        }
        public DateTime LastWritten => LastWrittenUtc.ToLocalTime();
        public DateTime LastWrittenUtc {
            get {
                lock(credentialNative) {
                    return DateTime.FromFileTimeUtc(unchecked((long)((uint)credentialNative.LastWritten.dwLowDateTime|(ulong)(uint)credentialNative.LastWritten.dwHighDateTime<<32)));
                }
            }
        }
        public string Comment {
            get {
                lock(credentialNative) {
                    return credentialNative.Comment;
                }
            }
            set {
                lock(credentialNative) {
                    credentialNative.Comment=value??string.Empty;
                }
            }
        }
        public void Delete() => Delete(SavedCredentialDeleteFlags.None);
        public void Delete(SavedCredentialDeleteFlags flags) {
            lock(credentialNative) {
                Delete(credentialNative.TargetName, credentialNative.Type, flags);
            }
        }
        public void Read() => Read(SavedCredentialReadFlags.None);
        [SecuritySafeCritical, SavedCredentialPermission(SecurityAction.Demand, Unrestricted = true), SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
        public void Read(SavedCredentialReadFlags flags) {
            lock(credentialNative) {
                IntPtr handle = IntPtr.Zero;
                RuntimeHelpers.PrepareConstrainedRegions();
                try {
                    NativeMethods.CredRead(credentialNative.TargetName, credentialNative.Type, flags, out handle);
                    Marshal.PtrToStructure(handle, credentialNative);
                    PostReadFixup();
                } finally {
                    if(handle!=IntPtr.Zero) {
                        NativeMethods.CredFree(handle);
                    }
                }
            }
        }
        public void Write() => Write(SavedCredentialWriteFlags.None);
        [SecuritySafeCritical, SavedCredentialPermission(SecurityAction.Demand, Unrestricted = true), SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
        public void Write(SavedCredentialWriteFlags flags) {
            lock(credentialNative) {
                credentialNative.CredentialBlob=IntPtr.Zero;
                RuntimeHelpers.PrepareConstrainedRegions();
                try {
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { } finally {
                        credentialNative.CredentialBlob=Marshal.SecureStringToBSTR(credentialBlob);
                    }
                    for(int i = 0; i<credentialBlob.Length; ++i) {
                        short t = Marshal.ReadInt16(credentialNative.CredentialBlob, i*2);
                        Marshal.WriteByte(credentialNative.CredentialBlob, i*2, unchecked((byte)t));
                        Marshal.WriteByte(credentialNative.CredentialBlob, i*2+1, unchecked((byte)(t>>8)));
                    }
                    credentialNative.AttributeCount=0;
                    credentialNative.Attributes=IntPtr.Zero;
                    NativeMethods.CredWrite(credentialNative, flags);
                } finally {
                    if(credentialNative.CredentialBlob!=IntPtr.Zero) {
                        Marshal.ZeroFreeBSTR(credentialNative.CredentialBlob);
                    }
                }
            }
        }
        [SecurityCritical]
        private void PostReadFixup() {
            if(credentialNative.TargetName==null) {
                credentialNative.TargetName=string.Empty;
            }
            if(credentialNative.TargetAlias==null) {
                credentialNative.TargetAlias=string.Empty;
            }
            if(credentialNative.UserName==null) {
                credentialNative.UserName=string.Empty;
            }
            if(credentialNative.Comment==null) {
                credentialNative.Comment=string.Empty;
            }
            credentialBlob.Clear();
            for(int i = 0; i<credentialNative.CredentialBlobSize/2; ++i) {
                credentialBlob.AppendChar((char)(Marshal.ReadByte(credentialNative.CredentialBlob, i*2)|Marshal.ReadByte(credentialNative.CredentialBlob, i*2+1)<<8));
            }
            if(credentialNative.CredentialBlobSize%2!=0) {
                credentialBlob.AppendChar((char)Marshal.ReadByte(credentialNative.CredentialBlob, credentialNative.CredentialBlobSize-1));
            }
        }
    }
}

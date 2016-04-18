using System;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
namespace PetSerAl.SavedCredentials {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal sealed class SavedCredentialNative {
        public int Flags;
        public SavedCredentialType Type;
        public string TargetName;
        public string Comment;
        public FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public SavedCredentialPersist Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
        public SavedCredentialNative() { }
    }
}

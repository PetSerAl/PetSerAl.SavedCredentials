using System;
using System.ComponentModel;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
namespace PetSerAl.SavedCredentials {
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal static class NativeMethods {
        public static void CredDelete(string targetName, SavedCredentialType type, SavedCredentialDeleteFlags flags) {
            if(!Extern.CredDelete(targetName, type, flags)) {
                throw new Win32Exception();
            }
        }
        public static void CredEnumerate(string filter, SavedCredentialEnumerateFlags flags, out int count, out IntPtr credentials) {
            if(!Extern.CredEnumerate(filter, flags, out count, out credentials)) {
                throw new Win32Exception();
            }
        }
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static void CredFree(IntPtr handle) => Extern.CredFree(handle);
        public static void CredRead(string targetName, SavedCredentialType type, SavedCredentialReadFlags flags, out IntPtr credential) {
            if(!Extern.CredRead(targetName, type, flags, out credential)) {
                throw new Win32Exception();
            }
        }
        public static void CredWrite(SavedCredentialNative credential, SavedCredentialWriteFlags flags) {
            if(!Extern.CredWrite(credential, flags)) {
                throw new Win32Exception();
            }
        }
        private static class Extern {
            [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CredDelete(string targetName, SavedCredentialType type, SavedCredentialDeleteFlags flags);
            [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CredEnumerate(string filter, SavedCredentialEnumerateFlags flags, out int count, out IntPtr credentials);
            [DllImport("Advapi32.dll"), SuppressUnmanagedCodeSecurity, ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            public static extern void CredFree(IntPtr handle);
            [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CredRead(string targetName, SavedCredentialType type, SavedCredentialReadFlags flags, out IntPtr credential);
            [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CredWrite(SavedCredentialNative credential, SavedCredentialWriteFlags flags);
        }
    }
}

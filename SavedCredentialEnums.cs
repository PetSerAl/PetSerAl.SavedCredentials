using System;
namespace PetSerAl.SavedCredentials {
    public enum SavedCredentialType {
        Generic = 1,
        DomainPassword,
        DomainCertificate,
        DomainVisiblePassword,
        GenericCertificate,
        DomainExtended,
        Maximum,
        MaximumEx = Maximum+1000
    }
    public enum SavedCredentialPersist {
        Session = 1,
        LocalMachine,
        Enterprise
    }
    [Flags]
    public enum SavedCredentialDeleteFlags {
        None
    }
    [Flags]
    public enum SavedCredentialEnumerateFlags {
        None,
        EnumerateAllCredentials
    }
    [Flags]
    public enum SavedCredentialReadFlags {
        None
    }
    [Flags]
    public enum SavedCredentialWriteFlags {
        None,
        PreserveCredentialBlob
    }
}

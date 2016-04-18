using System;
using System.Security;
using System.Security.Permissions;
namespace PetSerAl.SavedCredentials {
    public class SavedCredentialPermission : CodeAccessPermission, IUnrestrictedPermission {
        private static bool GetIsUnrestricted(IPermission target) {
            if(target==null) {
                return false;
            }
            SavedCredentialPermission credentialManagerPermission = target as SavedCredentialPermission;
            if(credentialManagerPermission==null) {
                throw new ArgumentException(null, nameof(target));
            }
            return credentialManagerPermission.IsUnrestricted();
        }
        private bool unrestricted;
        public SavedCredentialPermission(PermissionState state) {
            if(state==PermissionState.Unrestricted) {
                unrestricted=true;
            } else {
                if(state!=PermissionState.None) {
                    throw new ArgumentOutOfRangeException(nameof(state));
                }
            }
        }
        public bool IsUnrestricted() => unrestricted;
        public override bool IsSubsetOf(IPermission target) => !IsUnrestricted()||GetIsUnrestricted(target);
        public override IPermission Copy() => new SavedCredentialPermission(IsUnrestricted() ? PermissionState.Unrestricted : PermissionState.None);
        public override IPermission Intersect(IPermission target) => IsUnrestricted()&&GetIsUnrestricted(target) ? new SavedCredentialPermission(PermissionState.Unrestricted) : null;
        public override IPermission Union(IPermission target) => new SavedCredentialPermission(IsUnrestricted()||GetIsUnrestricted(target) ? PermissionState.Unrestricted : PermissionState.None);
        public override void FromXml(SecurityElement element) {
            if(element==null) {
                throw new ArgumentNullException(nameof(element));
            }
            if(element.Tag!="Permission"&&element.Tag!="IPermission") {
                throw new ArgumentException(null, nameof(element));
            }
            string version = element.Attribute("version");
            if(version!=null&&version!="1") {
                throw new ArgumentException(null, nameof(element));
            }
            bool.TryParse(element.Attribute("Unrestricted"), out unrestricted);
        }
        public override SecurityElement ToXml() {
            SecurityElement element = new SecurityElement("IPermission");
            element.AddAttribute("class", SecurityElement.Escape(typeof(SavedCredentialPermission).AssemblyQualifiedName));
            element.AddAttribute("version", "1");
            if(IsUnrestricted()) {
                element.AddAttribute("Unrestricted", bool.TrueString);
            }
            return element;
        }
    }
    public class SavedCredentialPermissionAttribute : CodeAccessSecurityAttribute {
        public SavedCredentialPermissionAttribute(SecurityAction action) : base(action) { }
        public override IPermission CreatePermission() => new SavedCredentialPermission(Unrestricted ? PermissionState.Unrestricted : PermissionState.None);
    }
}

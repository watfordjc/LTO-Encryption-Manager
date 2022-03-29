using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
    public class NativeMethods
    {
        public enum CRYPT_OID_INFO : uint
        {
            CRYPT_OID_INFO_OID_KEY = 1,
            CRYPT_OID_INFO_NAME_KEY = 2,
            CRYPT_OID_INFO_ALGID_KEY = 3,
            CRYPT_OID_INFO_SIGN_KEY = 4
        }

        public enum CRYPT_OID_GROUP : uint
        {
            CRYPT_ALL_OID_GROUP_ID = 0,
            CRYPT_HASH_ALG_OID_GROUP_ID = 1,
            CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2,
            CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3,
            CRYPT_SIGN_ALG_OID_GROUP_ID = 4,
            CRYPT_RDN_ATTR_OID_GROUP_ID = 5,
            CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6,
            CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7,
            CRYPT_POLICY_OID_GROUP_ID = 8,
            CRYPT_TEMPLATE_OID_GROUP_ID = 9,
            CRYPT_KDF_OID_GROUP_ID = 10
        }
    }
}

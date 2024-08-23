namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
	public static class NativeMethods
    {
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "dwKeyType IS DWORD")]
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "There is no CRYPT_OID_INFO key type 0")]
		public enum OidKeyType : uint		// CRYPT_OID_INFO
		{
			Oid = 1,						// CRYPT_OID_INFO_OID_KEY
			Name = 2,						// CRYPT_OID_INFO_NAME_KEY
			AlgorithmID = 3,				// CRYPT_OID_INFO_ALGID_KEY
			SignatureID = 4,				// CRYPT_OID_INFO_SIGN_KEY
			CngAlgorithmID = 5,				// CRYPT_OID_INFO_CNG_ALGID_KEY
			CngSignatureID = 6,				// CRYPT_OID_INFO_CNG_SIGN_KEY
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "dwGroupId is DWORD")]
		public enum OidGroup : uint			// CRYPT_OID_GROUP
		{
			AllGroups = 0,
			HashAlgorithm = 1,				// CRYPT_HASH_ALG_OID_GROUP_ID
			EncryptionAlgorithm = 2,		// CRYPT_ENCRYPT_ALG_OID_GROUP_ID
			PublicKeyAlgorithm = 3,			// CRYPT_PUBKEY_ALG_OID_GROUP_ID
			SignatureAlgorithm = 4,			// CRYPT_SIGN_ALG_OID_GROUP_ID
			Attribute = 5,					// CRYPT_RDN_ATTR_OID_GROUP_ID
			ExtensionOrAttribute = 6,		// CRYPT_EXT_OR_ATTR_OID_GROUP_ID
			EnhancedKeyUsage = 7,			// CRYPT_ENHKEY_USAGE_OID_GROUP_ID
			Policy = 8,						// CRYPT_POLICY_OID_GROUP_ID
			Template = 9,					// CRYPT_TEMPLATE_OID_GROUP_ID
			KeyDerivationFunction = 10,		// CRYPT_KDF_OID_GROUP_ID
		}
    }
}

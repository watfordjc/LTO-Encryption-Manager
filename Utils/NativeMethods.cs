namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
	/// <summary>
	/// Static methods and <see langword="enum"/> for use with Win32 P/Invoke.
	/// </summary>
	public static class NativeMethods
    {
		/// <summary>
		/// PCCRYPT_OID_INFO.dwKeyType (DWORD) parameter values, used to define the meaning of the search term when searching for a
		///   CRYPT_OID_INFO using <see cref="Windows.Win32.PInvoke.CryptFindOIDInfo(uint, void*, uint)"/>.
		/// </summary>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "dwKeyType IS DWORD")]
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "There is no CRYPT_OID_INFO key type 0")]
		public enum OidKeyType : uint
		{
			/// <summary>
			/// CRYPT_OID_INFO_OID_KEY: pvKey is the address of a null-terminated ANSI string that contains the OID string to find.
			/// </summary>
			Oid = 1,
			/// <summary>
			/// CRYPT_OID_INFO_NAME_KEY: pvKey is the address of a null-terminated Unicode string that contains the name to find.
			/// </summary>
			Name = 2,
			/// <summary>
			/// CRYPT_OID_INFO_ALGID_KEY: pvKey is the address of an ALG_ID variable.
			/// </summary>
			AlgorithmID = 3,
			/// <summary>
			/// CRYPT_OID_INFO_SIGN_KEY: pvKey is the address of an array of two ALG_IDs where the first element contains the hash algorithm
			///   identifier and the second element contains the public key algorithm identifier.
			/// </summary>
			SignatureID = 4,
			/// <summary>
			/// CRYPT_OID_INFO_CNG_ALGID_KEY: pvKey is the address of a null-terminated Unicode string that contains the CNG algorithm identifier to find.
			/// </summary>
			CngAlgorithmID = 5,
			/// <summary>
			/// CRYPT_OID_INFO_CNG_SIGN_KEY: pvKey is the address of an array of two null-terminated Unicode string pointers where the first string contains
			///   the hash CNG algorithm identifier and the second string contains the public key CNG algorithm identifier.
			/// </summary>
			CngSignatureID = 6,
		}

		/// <summary>
		/// Identifies Windows cryptographic object identifier (OID) groups (CRYPT_OID_GROUP).
		/// </summary>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "dwGroupId is DWORD")]
		public enum OidGroup : uint
		{
			/// <summary>
			/// All the groups.
			/// </summary>
			AllGroups = 0,
			/// <summary>
			/// The Windows group that is represented by CRYPT_HASH_ALG_OID_GROUP_ID.
			/// </summary>
			HashAlgorithm = 1,
			/// <summary>
			/// The Windows group that is represented by CRYPT_ENCRYPT_ALG_OID_GROUP_ID.
			/// </summary>
			EncryptionAlgorithm = 2,
			/// <summary>
			/// The Windows group that is represented by CRYPT_PUBKEY_ALG_OID_GROUP_ID.
			/// </summary>
			PublicKeyAlgorithm = 3,
			/// <summary>
			/// The Windows group that is represented by CRYPT_SIGN_ALG_OID_GROUP_ID.
			/// </summary>
			SignatureAlgorithm = 4,
			/// <summary>
			/// The Windows group that is represented by CRYPT_RDN_ATTR_OID_GROUP_ID.
			/// </summary>
			Attribute = 5,
			/// <summary>
			/// The Windows group that is represented by CRYPT_EXT_OR_ATTR_OID_GROUP_ID.
			/// </summary>
			ExtensionOrAttribute = 6,
			/// <summary>
			/// The Windows group that is represented by CRYPT_ENHKEY_USAGE_OID_GROUP_ID.
			/// </summary>
			EnhancedKeyUsage = 7,
			/// <summary>
			/// The Windows group that is represented by CRYPT_POLICY_OID_GROUP_ID.
			/// </summary>
			Policy = 8,
			/// <summary>
			/// The Windows group that is represented by CRYPT_TEMPLATE_OID_GROUP_ID.
			/// </summary>
			Template = 9,
			/// <summary>
			/// The Windows group that is represented by CRYPT_KDF_OID_GROUP_ID.
			/// </summary>
			KeyDerivationFunction = 10
		}
    }
}

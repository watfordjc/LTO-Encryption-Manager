using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
	public static class PKI
	{
		static readonly Windows.Win32.Foundation.BOOL FALSE = (Windows.Win32.Foundation.BOOL)0;
		static readonly Windows.Win32.Foundation.BOOL TRUE = (Windows.Win32.Foundation.BOOL)1;

		static bool TryUnregisterOid(Windows.Win32.Security.Cryptography.CRYPT_OID_INFO oidInfo)
		{
			return Windows.Win32.PInvoke.CryptUnregisterOIDInfo(oidInfo) != FALSE;
		}

		public static void UpdateOidFriendlyNames(OidCollection oids, bool forceRefresh = false)
		{
			ArgumentNullException.ThrowIfNull(oids);
			foreach (Oid oid in oids)
			{
				Windows.Win32.Security.Cryptography.CRYPT_OID_INFO? currentOidInfo = null;
				uint CRYPT_OID_INFO_OID_KEY = (uint)NativeMethods.OidKeyType.Oid;
				IntPtr oidValuePtr = IntPtr.Zero;
				Windows.Win32.Foundation.PCSTR? pszOID = null;
				Windows.Win32.Security.Cryptography.CRYPT_OID_INFO oidInfo = new();
				try
				{
					oidValuePtr = Marshal.StringToHGlobalAnsi(oid.Value);
					unsafe
					{
						byte* oidValue = (byte*)oidValuePtr;
						pszOID = new(oidValue);
						Windows.Win32.Security.Cryptography.CRYPT_OID_INFO* oidPtr = Windows.Win32.PInvoke.CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, &pszOID, 0);
						if ((IntPtr)oidPtr != IntPtr.Zero)
						{
							currentOidInfo = *oidPtr;
							string? currentOidValue = Marshal.PtrToStringAnsi(oidValuePtr);
							if (currentOidValue is not null && currentOidValue.Equals(oid.Value, StringComparison.Ordinal) && !forceRefresh)
							{
								Marshal.FreeHGlobal(oidValuePtr);
								continue;
							}
						}
					}
				}
				// Marshal.StringToHGlobalAnsi (OutOfMemoryException) // There is insufficient memory available.
				// Marshal.StringToHGlobalAnsi (ArgumentOutOfRangeException) // The s parameter exceeds the maximum length allowed by the operating system.
				// string.Equals (ArgumentException) // comparisonType is not a System.StringComparison value.
				// Oid.Value (PlatformNotSupportedException) // .NET 5 and later: An attempt is made to set the value and the value has previously been set.
				catch (Exception ex) when
				(ex is OutOfMemoryException || ex is ArgumentOutOfRangeException || ex is ArgumentException || ex is PlatformNotSupportedException)
				{
					if (oidValuePtr != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(oidValuePtr);
						return;
					}
				}
				catch (Exception ex2)
				{
					throw new UnreachableException("Unhandled exception.", ex2);
				}
				IntPtr oidNamePtr = IntPtr.Zero;
				if (pszOID is null)
				{
					return;
				}
				try
				{
					oidNamePtr = Marshal.StringToHGlobalUni(oid.FriendlyName);
					uint CRYPT_ENHKEY_USAGE_OID_GROUP_ID = (uint)NativeMethods.OidGroup.EnhancedKeyUsage;
					unsafe
					{
						oidInfo.pszOID = pszOID.Value;
						char* oidName = (char*)oidNamePtr;
						oidInfo.pwszName = (Windows.Win32.Foundation.PCWSTR)oidName;
						oidInfo.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID;
						oidInfo.cbSize = (uint)Marshal.SizeOf(oidInfo);
						Windows.Win32.PInvoke.CryptRegisterOIDInfo(oidInfo, 0);
					}
				}
				// Marshal.StringToHGlobalAnsi (OutOfMemoryException) // There is insufficient memory available.
				// Marshal.StringToHGlobalAnsi (ArgumentOutOfRangeException) // The s parameter exceeds the maximum length allowed by the operating system.
				// PCSTR?.Value (InvalidOperationException) // The System.Nullable`1.HasValue property is false.
				// Marshal.SizeOf (ArgumentNullException) // The structure parameter is null.
				catch (Exception ex) when
				(ex is OutOfMemoryException || ex is ArgumentOutOfRangeException || ex is InvalidOperationException || ex is ArgumentNullException)
				{
					if (oidNamePtr != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(oidValuePtr);
						Marshal.FreeHGlobal(oidNamePtr);
						return;
					}
				}
				catch (Exception ex2)
				{
					throw new UnreachableException("Unhandled exception.", ex2);
				}
				Marshal.FreeHGlobal(oidValuePtr);
				Marshal.FreeHGlobal(oidNamePtr);
			}
		}

		/// <summary>
		/// Try to get an RSA key by its name
		/// </summary>
		/// <param name="keyName">The name of the key</param>
		/// <param name="rsaCng">The key if it exists</param>
		/// <returns>true on success, otherwise false</returns>
		public static RSACng? GetRsaKeyByName(string keyName)
		{
			CngProvider tpmCryptoProvider = CngProvider.MicrosoftPlatformCryptoProvider;

			bool tpmKeyExists;
			try
			{
				tpmKeyExists = CngKey.Exists(keyName, tpmCryptoProvider, CngKeyOpenOptions.None);
			}
			// CngKey.Exists (ArgumentNullException): keyName argument is null
			// CngKey.Exists (PlatformNotSupportedException): CNG is not supported
			// CngKey.Exists (CryptographicException): all other errors
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is PlatformNotSupportedException || ex is CryptographicException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}

			if (!tpmKeyExists)
			{
				return null;
			}

			try
			{
				using CngKey cngKey = CngKey.Open(keyName, tpmCryptoProvider, CngKeyOpenOptions.None);
				return new(cngKey);
			}
			// CngKey.Open (ArgumentNullException): keyName argument is null
			// CngKey.Open (PlatformNotSupportedException): CNG is not supported
			// CngKey.Open (CryptographicException): all other errors
			// RsaCng.ctor (ArgumentException): key argument is not an RSA key
			// RSACng.ctor (ArgumentNullException): key argument is null
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is PlatformNotSupportedException || ex is CryptographicException || ex is ArgumentException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
		}

		public static RSACng? CreateRsaKey(string keyName)
		{
			string keyCreateDescription = "Encrypting/decrypting account keys, and signing/verifying account records, in LTO Encryption Manager.";
			string keyUseContext = keyCreateDescription;
			CngKeyCreationParameters creationParameters = new()
			{
				ExportPolicy = CngExportPolicies.None,
				KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
				Provider = CngProvider.MicrosoftPlatformCryptoProvider,
				UIPolicy = new(CngUIProtectionLevels.ProtectKey, keyName, keyCreateDescription, keyUseContext),
				KeyCreationOptions = CngKeyCreationOptions.None
			};
			CngProperty keySize;
			try
			{
				keySize = new("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None);
			}
			// CngProperty.ctor (ArgumentNullException): name argument is null
			catch (ArgumentNullException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
			creationParameters.Parameters.Add(keySize);

			try
			{
				using CngKey cngKey = CngKey.Create(CngAlgorithm.Rsa, keyName, creationParameters);
				return new(cngKey);
			}
			// CngKey.Create (ArgumentNullException): algorithm argument is null
			// CngKey.Create (PlatformNotSupportedException): CNG is not supported
			// CngKey.Create (CryptographicException): all other errors
			// RsaCng.ctor (ArgumentException): key argument is not an RSA key
			// RSACng.ctor (ArgumentNullException): key argument is null
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is PlatformNotSupportedException || ex is CryptographicException || ex is ArgumentException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
		}

		/// <summary>
		/// Try to get a valid certificate where all <paramref name="requiredOids"/> are explicitly specified in extended key usages
		/// </summary>
		/// <param name="requiredOids">OIDs for key purposes that a valid certificate must explicitly specify</param>
		/// <param name="certificate">The first valid certificate found, if any</param>
		/// <returns>true on success, otherwise false</returns>
		public static bool TryGetValidCertificate(OidCollection requiredOids, [NotNullWhen(true)] out X509Certificate2? certificate)
		{
			ArgumentNullException.ThrowIfNull(requiredOids);
			certificate = null;

			try
			{
				using X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
				my.Open(OpenFlags.ReadOnly);
				X509Certificate2Collection certificates = my.Certificates.Find(X509FindType.FindByApplicationPolicy, "1.2.826.0.1.11484356.1.0.0.3.0", false);
				X509Certificate2Collection unexpiredCertificates = certificates.Find(X509FindType.FindByTimeValid, DateTime.UtcNow, false);
				foreach (X509Certificate2 cert in unexpiredCertificates)
				{
					if (cert.Archived || !cert.HasPrivateKey)
					{
						continue;
					}
					Oid extendedKeyUsageExtensionOid = Oid.FromOidValue("2.5.29.37", OidGroup.All);
					X509ExtensionCollection certExtensions = cert.Extensions;
					X509Extension? certEKUExtension = extendedKeyUsageExtensionOid.Value != null ? certExtensions[extendedKeyUsageExtensionOid.Value] : null;
					if (certEKUExtension == null)
					{
						continue;
					}
					X509EnhancedKeyUsageExtension certEKU = (X509EnhancedKeyUsageExtension)certEKUExtension;
					bool skipCertificate = false;
					foreach (Oid requiredOid in requiredOids)
					{
						if (!skipCertificate && requiredOid.Value != null && certEKU.EnhancedKeyUsages[requiredOid.Value] == null)
						{
							skipCertificate = true;
						}
					}
					if (!skipCertificate)
					{
						my.Close();
						certificate = cert;
						return true;
					}
				}
				my.Close();
				return false;
			}
			// X509Store.X509Store (ArgumentException) // storeLocation is not a valid location or storeName is not a valid name.
			// X509Store.Open (CryptographicException) // The store cannot be opened as requested.
			// X509Store.Open (SecurityException) // The caller does not have the required permission.
			// X509Store.Open (ArgumentException) // The store contains invalid values.
			// X509Certificate2Collection.Find (CryptographicException) // findType is invalid.
			// X509Certificate2.Archived (CryptographicException) // The certificate is unreadable.
			// X509Certificate2.Extensions (CryptographicException) // The certificate is unreadable.
			// X509Certificate2.HasPrivateKey (CryptographicException) // The certificate context is invalid.
			// Oid.FromOidValue (ArgumentNullException) // oidValue is null.
			// Oid.FromOidValue (CryptographicException) // The friendly name for the OID value was not found.
			// Oid.Value (PlatformNotSupportedException) // .NET 5 and later: An attempt is made to set the value and the value has previously been set.
			catch (Exception ex) when
			(ex is ArgumentException || ex is CryptographicException || ex is SecurityException || ex is ArgumentNullException || ex is PlatformNotSupportedException)
			{
				return false;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
		}

		/// <summary>
		/// Try to get a TPM-backed certificate, or try to create one
		/// </summary>
		/// <param name="certificate">The retrieved or created certificate</param>
		/// <param name="updateSystemOids">Whether system OID database should be updated (true) or not (false)</param>
		/// <returns>true on success, otherwise false</returns>
		public static X509Certificate2? GetOrCreateRsaCertificate(bool updateSystemOids = false, bool forceRefreshSystemOids = false)
		{

			OidCollection ekuOids = [];
			Oid idKpLtoEncryptionManagerOid = new("1.2.826.0.1.11484356.1.0.0.3.0", "Encrypting/decrypting account keys, and signing/verifying account records, in LTO Encryption Manager");
			ekuOids.Add(idKpLtoEncryptionManagerOid);

			if (updateSystemOids)
			{
				UpdateOidFriendlyNames(ekuOids, forceRefreshSystemOids);
			}

			string keyName = "LTO Encryption Manager account protection";
			using RSACng? rsaCng = GetRsaKeyByName(keyName) ?? CreateRsaKey(keyName);
			if (rsaCng is not null && rsaCng.Key.ExportPolicy != CngExportPolicies.None)
			{
				rsaCng.Dispose();
			}
			else if (rsaCng is null)
			{
				return null;
			}

			bool tpmKeyExists;
			try
			{
				tpmKeyExists = CngKey.Exists(keyName, CngProvider.MicrosoftPlatformCryptoProvider, CngKeyOpenOptions.None);
			}
			// CngKey.Exists (ArgumentNullException): keyName argument is null
			// CngKey.Exists (PlatformNotSupportedException): CNG is not supported
			// CngKey.Exists (CryptographicException): all other errors
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is PlatformNotSupportedException || ex is CryptographicException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}

			// If a key exists and TryGetRsaKeyByName() returned false, the key is not usable
			if (tpmKeyExists && rsaCng.Key.ExportPolicy != CngExportPolicies.None)
			{
				return null;
			}

			if (TryGetValidCertificate(ekuOids, out X509Certificate2? certificate))
			{
				return certificate;
			}

			CertificateRequest certificateRequest;
			X500DistinguishedName distinguishedName = new("CN=LTO Encryption Manager", X500DistinguishedNameFlags.None);
			try
			{
				certificateRequest = new(distinguishedName, rsaCng, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
			}
			// CertificateRequest.ctor (ArgumentNullException): arguments subjectName and/or key are null
			// CertificateRequest.ctor (ArgumentException): argument hashAlgorithm has a Name that is null or empty
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is ArgumentException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
			X509BasicConstraintsExtension basicConstraintsExtension = new(false, false, 0, false);
			certificateRequest.CertificateExtensions.Add(basicConstraintsExtension);
			X509KeyUsageExtension keyUsageExtension = new(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, true);
			certificateRequest.CertificateExtensions.Add(keyUsageExtension);
			X509SubjectKeyIdentifierExtension subjectKeyIdentifierExtension = new(certificateRequest.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha1, false);
			certificateRequest.CertificateExtensions.Add(subjectKeyIdentifierExtension);
			X509EnhancedKeyUsageExtension enhancedKeyUsageExtension;
			try
			{
				enhancedKeyUsageExtension = new(ekuOids, true);
			}
			// X509EnhancedKeyUsageExtension.ctor (CryptographicException): argument enhancedKeyUsages contains one or more corrupt values
			catch (CryptographicException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
			certificateRequest.CertificateExtensions.Add(enhancedKeyUsageExtension);
			try
			{
				DateTimeOffset notBefore = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
				DateTimeOffset notAfter = DateTimeOffset.UtcNow + TimeSpan.FromDays(90);
				certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);
			}
			// TimeSpan.X (OverflowException) // value is less than TimeSpan.MinValue or greater than TimeSpan.MaxValue. -or- value is System.Double.PositiveInfinity. -or- value is System.Double.NegativeInfinity.
			// TimeSpan.X (ArgumentException) // value is equal to System.Double.NaN.
			// CertificateRequest.CreateSelfSigned (ArgumentException): argument notAfter is earlier than argument notBefore
			// CertificateRequest.CreateSelfSigned (InvalidOperationException): the CertificateRequest.ctor used doesn't accept a signing key
			// CertificateRequest.CreateSelfSigned (CryptographicException): an error occurred creating the certificate
			// CertificateRequest.CreateSelfSigned (ArgumentOutOfRangeException): the CertificateRequest.HashAlgorithm is not supported
			catch (Exception ex) when
			(ex is OverflowException || ex is ArgumentException || ex is InvalidOperationException || ex is CryptographicException || ex is ArgumentOutOfRangeException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}

			certificate.FriendlyName = "LTO Encryption Manager";
			try
			{
				using X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
				my.Open(OpenFlags.ReadWrite);
				my.Add(certificate);
				my.Close();
				return certificate;
			}
			// X509Store.ctor (ArgumentException): argument storeLocation is not a valid location or argument storeName is not a valid name
			// X509Store.Open (CryptographicException): the store cannot be opened as requested
			// X509Store.Open (SecurityException): the caller does not have the required permission
			// X509Store.Open (ArgumentException): the store contains invalid values
			// X509Store.Add (ArgumentNullException): the certificate argument is null
			// X509Store.Add (CryptographicException): the certificate could not be added to the store
			catch (Exception ex) when
			(ex is ArgumentException || ex is CryptographicException || ex is SecurityException || ex is ArgumentNullException)
			{
				return null;
			}
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
		}
	}
}

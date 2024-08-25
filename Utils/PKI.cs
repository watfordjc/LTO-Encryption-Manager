using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Windows.Win32.Foundation;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
	public static class PKI
	{
		// Win32 FALSE = 0
		static readonly BOOL FALSE = (BOOL)0;
		// Win32 TRUE = 1
		static readonly BOOL TRUE = (BOOL)1;

		/// <summary>
		/// Try to remove the registration of an OID from the system
		/// </summary>
		/// <param name="oidInfo">The OID to unregister.</param>
		/// <returns><c>true</c> if <see cref="Windows.Win32.PInvoke.CryptUnregisterOIDInfo(in Windows.Win32.Security.Cryptography.CRYPT_OID_INFO)"/> does not return <c>FALSE</c>, else returns <c>false</c>.</returns>
		static bool TryUnregisterOid(Windows.Win32.Security.Cryptography.CRYPT_OID_INFO oidInfo)
		{
			return Windows.Win32.PInvoke.CryptUnregisterOIDInfo(oidInfo) != FALSE;
		}

		/// <summary>
		/// Copies a <see cref="string"/> to a <see cref="PCSTR"/>
		/// </summary>
		/// <param name="inputString">The <see cref="string"/> to copy.</param>
		/// <returns>The <see cref="PCSTR"/> equivalent of <paramref name="inputString"/>.</returns>
		/// <exception cref="UnreachableException">Thrown if an <see cref="Exception"/> occurs that is not silently handled.</exception>
		internal static PCSTR? StringToPCSTR(string inputString)
		{
			// Throw exception if non-nullable parameters are null
			ArgumentNullException.ThrowIfNull(inputString);
			// A pointer to hold the ANSI string
			IntPtr nativeStringPtr = IntPtr.Zero;
			// Try to convert the string
			try
			{
				// Copy the string to an ANSI string
				nativeStringPtr = Marshal.StringToHGlobalAnsi(inputString);
				// As value is not null, StringToHGlobalAnsi() should not return 0
				if (nativeStringPtr == IntPtr.Zero)
				{
					return null;
				}
				// Working with pointers requires unsafe context
				unsafe
				{
					// Cast the IntPtr to the ANSI string, to a C byte* pointer/array
					byte* byteArray = (byte*)nativeStringPtr;
					// Create a native ANSI string from the byte* array and return it
					return new(byteArray);
				}
			}
			// Catch all expected Exception types:
			// Marshal.StringToHGlobalAnsi (OutOfMemoryException)
			// Marshal.StringToHGlobalAnsi (ArgumentOutOfRangeException)
			catch (Exception ex) when
			(ex is OutOfMemoryException || ex is ArgumentOutOfRangeException)
			{
				return null;
			}
			// All Exception types should be handled above - if not, the above needs fixing
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
			finally
			{
				// Free the ANSI string pointer
				Marshal.FreeHGlobal(nativeStringPtr);
			}
		}

		/// <summary>
		/// Copies a <see cref="string"/> to a <see cref="PCWSTR"/>
		/// </summary>
		/// <param name="inputString">The <see cref="string"/> to copy.</param>
		/// <returns>The <see cref="PCWSTR"/> equivalent of <paramref name="inputString"/>.</returns>
		/// <exception cref="UnreachableException">Thrown if an <see cref="Exception"/> occurs that is not silently handled.</exception>
		internal static PCWSTR? StringToPCWSTR(string inputString)
		{
			// Throw exception if non-nullable parameters are null
			ArgumentNullException.ThrowIfNull(inputString);
			// A pointer to hold the UTF-16 string
			IntPtr nativeStringPtr = IntPtr.Zero;
			// Try to convert the string
			try
			{
				// Copy the string to an UTF-16 string
				nativeStringPtr = Marshal.StringToHGlobalUni(inputString);
				// As value is not null, StringToHGlobalUni() should not return 0
				if (nativeStringPtr == IntPtr.Zero)
				{
					return null;
				}
				// Working with pointers requires unsafe context
				unsafe
				{
					// Cast the IntPtr to the UTF-16 string, to a C char* pointer/array
					char* charArray = (char*)nativeStringPtr;
					// Create a native UTF-16 string from the byte* array and return it
					return new(charArray);
				}
			}
			// Catch all expected Exception types:
			// Marshal.StringToHGlobalUni (OutOfMemoryException)
			// Marshal.StringToHGlobalUni (ArgumentOutOfRangeException)
			catch (Exception ex) when
			(ex is OutOfMemoryException || ex is ArgumentOutOfRangeException)
			{
				return null;
			}
			// All Exception types should be handled above - if not, the above needs fixing
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
			finally
			{
				// Free the UTF-16 string pointer
				Marshal.FreeHGlobal(nativeStringPtr);
			}
		}

		/// <summary>
		/// Searches the system for a registered <see cref="Oid"/>
		/// </summary>
		/// <param name="oid">The <see cref="Oid"/> to search for.</param>
		/// <param name="currentOidInfo">The found OID, as a native <see cref="Windows.Win32.Security.Cryptography.CRYPT_OID_INFO"/> struct.</param>
		/// <returns><c>true</c> if found, <c>false</c> if not found or an error occurred.</returns>
		/// <exception cref="UnreachableException">Thrown if an <see cref="Exception"/> occurs that is not silently handled.</exception>
		internal static bool TryGetSystemRegisteredOid(Oid oid, [NotNullWhen(true)] out Windows.Win32.Security.Cryptography.CRYPT_OID_INFO? currentOidInfo)
		{
			// Throw exception if non-nullable parameters are null
			ArgumentNullException.ThrowIfNull(oid);
			// Initialise outputs to null
			currentOidInfo = null;
			// An Oid with a null/empty dotted-decimal value is invalid and won't be registered on the system
			if (string.IsNullOrEmpty(oid.Value))
			{
				return false;
			}

			// The CRYPT_OID_INFO key type value CRYPT_OID_INFO_OID_KEY
			uint CRYPT_OID_INFO_OID_KEY = (uint)NativeMethods.OidKeyType.Oid;

			// Convert the dotted-decimal OID value to an ANSI string
			PCSTR? pszOID = StringToPCSTR(oid.Value);
			if (pszOID is null)
			{
				return false;
			}

			// Try to get the system-registered OID, if it already exists
			try
			{
				// Working with pointers requires unsafe context
				unsafe
				{
					// Get a native CRYPT_OID_INFO* pointer for the system-registered OID
					Windows.Win32.Security.Cryptography.CRYPT_OID_INFO* oidPtr = Windows.Win32.PInvoke.CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pszOID, 0);
					// If NULL is returned, the OID is not already registered on the system
					if ((IntPtr)oidPtr == IntPtr.Zero)
					{
						return false;
					}
					// Update the nullable native CRYPT_OID_INFO struct so it points to the returned system-registered OID
					currentOidInfo = *oidPtr;
					// Double-check the dotted-decimal value of the found OID matches what was searched for
					return currentOidInfo.Value.pszOID.AsSpan().SequenceEqual(pszOID.Value.AsSpan());
				}
			}
			// Catch all expected Exception types:
			// string.Equals (ArgumentException)
			// Oid.Value (PlatformNotSupportedException)
			catch (Exception ex) when
			(ex is ArgumentException || ex is PlatformNotSupportedException)
			{
				return false;
			}
			// All Exception types should be handled above - if not, the above needs fixing
			catch (Exception ex2)
			{
				throw new UnreachableException("Unhandled exception.", ex2);
			}
		}

		/// <summary>
		/// Try to update the system's Friendly Names for a collection of OIDs - does not give confirmation of success/failure
		/// </summary>
		/// <param name="oids">A collection of <see cref="Oid"/>s.</param>
		/// <param name="forceRefresh">Whether any <see cref="Oid"/>s in the collection already known by the system should have their Friendly Names updated.</param>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <c>null</c>.</exception>
		/// <exception cref="UnreachableException">Thrown if an <see cref="Exception"/> occurs that is not silently handled.</exception>
		public static void UpdateOidFriendlyNames(OidCollection oids, bool forceRefresh = false)
		{
			// Throw exception if non-nullable parameters are null
			ArgumentNullException.ThrowIfNull(oids);
			// The CRYPT_OID_INFO.dwGroupId value CRYPT_ENHKEY_USAGE_OID_GROUP_ID
			uint CRYPT_ENHKEY_USAGE_OID_GROUP_ID = (uint)NativeMethods.OidGroup.EnhancedKeyUsage;
			// Cycle through each Oid in the OidCollection
			foreach (Oid oid in oids)
			{
				// An Oid with a null/empty dotted-decimal value is invalid
				if (string.IsNullOrEmpty(oid.Value))
				{
					continue;
				}
				// See if the current OID is already registered on the system, and if so get it as an CRYPT_OID_INFO struct
				bool oidAlreadyRegistered = TryGetSystemRegisteredOid(oid, out Windows.Win32.Security.Cryptography.CRYPT_OID_INFO? currentOidInfo);
				// If the OID is already registered and we're not forcing an update, go to the next Oid
				if (oidAlreadyRegistered && !forceRefresh)
				{
					continue;
				}

				// Convert the Friendly Name to a native UTF-16 string
				PCWSTR? friendlyName = oid.FriendlyName is not null ? StringToPCWSTR(oid.FriendlyName) : null;
				// Initialise a native CRYPT_OID_INFO for holding the new information of the OID to be updated/registered
				Windows.Win32.Security.Cryptography.CRYPT_OID_INFO oidInfo = new();
				// Try to register/update the OID's information on the system
				try
				{
					// Create a variable for the dotted-decimal OID value as an ANSI string
					PCSTR? oidValue = currentOidInfo?.pszOID ?? StringToPCSTR(oid.Value);
					// If the OID value is null, go to the next OID
					if (!oidValue.HasValue)
					{
						continue;
					}
					// Set the dotted-decimal OID value
					oidInfo.pszOID = oidValue.Value;
					// Set the OID group ID
					oidInfo.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID;
					// If the OID has a Friendly Name, set it
					if (friendlyName.HasValue)
					{
						oidInfo.pwszName = friendlyName.Value;
					}
					// Get and set the size of the CRYPT_OID_INFO object
					oidInfo.cbSize = (uint)Marshal.SizeOf(oidInfo);
					// Try to register/update the OID on the system
					Windows.Win32.PInvoke.CryptRegisterOIDInfo(oidInfo, 0);
				}
				// Catch all expected Exception types:
				// PCSTR?.Value (InvalidOperationException)
				// PCWSTR?.Value (InvalidOperationException)
				// Marshal.SizeOf (ArgumentNullException)
				catch (Exception ex) when
				(ex is InvalidOperationException || ex is ArgumentNullException)
				{
					// Silently give up
					return;
				}
				// All Exception types should be handled above - if not, the above needs fixing
				catch (Exception ex2)
				{
					throw new UnreachableException("Unhandled exception.", ex2);
				}
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
		/// Get/create a TPM-backed certificate
		/// </summary>
		/// <param name="updateSystemOids">Whether system OID database should be updated (true) or not (false)</param>
		/// <param name="forceRefreshSystemOids">If <paramref name="updateSystemOids"/> is <c>true</c>, whether existing system-registered OIDs should also be updated</param>
		/// <returns>The retrieved or created certificate, or <c>null</c></returns>
		public static X509Certificate2? GetOrCreateRsaCertificate(bool updateSystemOids = false, bool forceRefreshSystemOids = false)
		{
			// Initialise a new collection of Oids that will store the EKU OIDs required in the certificate
			OidCollection ekuOids = [];
			// Add the application's EKU OID to the collection
			Oid idKpLtoEncryptionManagerOid = new("1.2.826.0.1.11484356.1.0.0.3.0", "Encrypting/decrypting account keys, and signing/verifying account records, in LTO Encryption Manager");
			ekuOids.Add(idKpLtoEncryptionManagerOid);

			// Try to update the system OID database if the parameter requested it
			if (updateSystemOids)
			{
				UpdateOidFriendlyNames(ekuOids, forceRefreshSystemOids);
			}

			// The 'name' of our RSA key
			string keyName = "LTO Encryption Manager account protection";
			// Get or create a TPM-backed RSA key
			using RSACng? rsaCng = GetRsaKeyByName(keyName) ?? CreateRsaKey(keyName);
			// Check the key was found/created and it is not exportable
			if (rsaCng is not null && rsaCng.Key.ExportPolicy != CngExportPolicies.None)
			{
				rsaCng.Dispose();
			}
			// Something went wrong finding/creating a TPM-backed key
			else if (rsaCng is null)
			{
				return null;
			}

			// If a key was found, verify it is a TPM-backed key
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

			// If a valid certificate already exists, return it
			if (TryGetValidCertificate(ekuOids, out X509Certificate2? certificate))
			{
				return certificate;
			}

			// If a valid certificate doesn't exist, we need to try and create one
			// Create a variable to hold a CSR
			CertificateRequest certificateRequest;
			// Create a variable to hold a distinguished name
			X500DistinguishedName distinguishedName = new("CN=LTO Encryption Manager", X500DistinguishedNameFlags.None);
			try
			{
				// Create a new basic CSR for our distinguished name and TPM-backed RSA key, using SHA-256 and PKCS1 padding
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

			// Add some extensions to our CSR
			// Create a basic constraints extension: our certificate is not a CA cert, there are no path length restrictions - this extension is marked not critical
			X509BasicConstraintsExtension basicConstraintsExtension = new(false, false, 0, false);
			// Add the basic constraints extension to our CSR
			certificateRequest.CertificateExtensions.Add(basicConstraintsExtension);
			// Create a key usage extension: key can be used for encrypting and signing - this extension is marked critical
			X509KeyUsageExtension keyUsageExtension = new(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, true);
			// Add our key usage extension to our CSR
			certificateRequest.CertificateExtensions.Add(keyUsageExtension);
			// Create a subject key identifier extension, using our public key and SHA-1 - this extension is not marked critical
			X509SubjectKeyIdentifierExtension subjectKeyIdentifierExtension = new(certificateRequest.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha1, false);
			// Add our subject key identifier extension to the CSR
			certificateRequest.CertificateExtensions.Add(subjectKeyIdentifierExtension);
			// Create an enhanced key usage extension, adding the EKU OIDs our certificate requires - this extension is marked critical
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
			// Add our enhanced key usage extenion to our CSR
			certificateRequest.CertificateExtensions.Add(enhancedKeyUsageExtension);

			// Try to turn our CSR into a self-signed certificate
			try
			{
				// Make the certificate valid from one hour ago (covers incorrect daylight savings time system setting)
				DateTimeOffset notBefore = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
				// Make the certificate valid for 90 days
				DateTimeOffset notAfter = DateTimeOffset.UtcNow + TimeSpan.FromDays(90);
				// Try to create a self-signed certificate from the CSR
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

			// Add a Friendly Name to our certificate
			certificate.FriendlyName = "LTO Encryption Manager";
			try
			{
				// Open the user certificate store for the current user in read/write mode
				using X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
				my.Open(OpenFlags.ReadWrite);
				// Add the new certificate to the user certificate store
				my.Add(certificate);
				// Close the certificate store
				my.Close();
				// Return the new certificate
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

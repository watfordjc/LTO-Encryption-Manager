using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
    public class PKI
    {
        static readonly Windows.Win32.Foundation.BOOL FALSE = (Windows.Win32.Foundation.BOOL)0;
        static readonly Windows.Win32.Foundation.BOOL TRUE = (Windows.Win32.Foundation.BOOL)1;

        static bool TryUnregisterOid(Windows.Win32.Security.Cryptography.CRYPT_OID_INFO oidInfo)
        {
            return Windows.Win32.PInvoke.CryptUnregisterOIDInfo(oidInfo) != FALSE;
        }

        public static void UpdateOidFriendlyNames(OidCollection oids, bool forceRefresh = false)
        {
            foreach (Oid oid in oids)
            {
                Windows.Win32.Security.Cryptography.CRYPT_OID_INFO? currentOidInfo = null;
                uint CRYPT_OID_INFO_OID_KEY = (uint)NativeMethods.CRYPT_OID_INFO.CRYPT_OID_INFO_OID_KEY;
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
                            if (currentOidValue is not null && currentOidValue.Equals(oid.Value) && !forceRefresh)
                            {
                                Marshal.FreeHGlobal(oidValuePtr);
                                continue;
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    if (oidValuePtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(oidValuePtr);
                        return;
                    }
                }
                IntPtr oidNamePtr = IntPtr.Zero;
                if (pszOID is null)
                {
                    return;
                }
                try
                {
                    oidNamePtr = Marshal.StringToHGlobalUni(oid.FriendlyName);
                    unsafe
                    {
                        oidInfo.pszOID = pszOID.Value;
                        char* oidName = (char*)oidNamePtr;
                        oidInfo.pwszName = (Windows.Win32.Foundation.PCWSTR)oidName;
                        oidInfo.dwGroupId = (uint)NativeMethods.CRYPT_OID_GROUP.CRYPT_ENHKEY_USAGE_OID_GROUP_ID;
                        oidInfo.cbSize = (uint)Marshal.SizeOf(oidInfo);
                        Windows.Win32.PInvoke.CryptRegisterOIDInfo(oidInfo, 0);
                    }
                }
                catch (Exception)
                {
                    if (oidNamePtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(oidValuePtr);
                        Marshal.FreeHGlobal(oidNamePtr);
                        return;
                    }
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
        public static bool TryGetRsaKeyByName(string keyName, [NotNullWhen(true)] out RSACng? rsaCng)
        {
            rsaCng = null;

            CngProvider tpmCryptoProvider = CngProvider.MicrosoftPlatformCryptoProvider;

            bool tpmKeyExists;
            try
            {
                tpmKeyExists = CngKey.Exists(keyName, tpmCryptoProvider, CngKeyOpenOptions.None);
            }
            // CngKey.Exists (ArgumentNullException): keyName argument is null
            // CngKey.Exists (PlatformNotSupportedException): CNG is not supported
            // CngKey.Exists (CryptographicException): all other errors
            catch (Exception)
            {
                return false;
            }

            if (!tpmKeyExists)
            {
                return false;
            }

            CngKey cngKey;

            try
            {
                cngKey = CngKey.Open(keyName, tpmCryptoProvider, CngKeyOpenOptions.None);
            }
            // CngKey.Open (ArgumentNullException): keyName argument is null
            // CngKey.Open (PlatformNotSupportedException): CNG is not supported
            // CngKey.Open (CryptographicException): all other errors
            catch (Exception)
            {
                return false;
            }

            try
            {
                rsaCng = new(cngKey);
            }
            // RsaCng.ctor (ArgumentException): key argument is not an RSA key
            // RSACng.ctor (ArgumentNullException): key argument is null
            catch (Exception)
            {
                return false;
            }

            // Application security policy: Key must be non-exportable
            return rsaCng.Key.ExportPolicy == CngExportPolicies.None;
        }

        /// <summary>
        /// Try to retreive a TPM-wrapped RSA key, or try to create one if none exists
        /// </summary>
        /// <param name="rsaCng">The retrieved or created RSA key</param>
        /// <returns>true on success, otherwise false</returns>
        public static bool TryGetOrCreateRsaKey([NotNullWhen(true)] out RSACng? rsaCng)
        {
            CngProvider tpmCryptoProvider = CngProvider.MicrosoftPlatformCryptoProvider;

            string keyName = "LTO Encryption Manager account protection";

            if (TryGetRsaKeyByName(keyName, out rsaCng))
            {
                return true;
            }

            bool tpmKeyExists;
            try
            {
                tpmKeyExists = CngKey.Exists(keyName, tpmCryptoProvider, CngKeyOpenOptions.None);
            }
            // CngKey.Exists (ArgumentNullException): keyName argument is null
            // CngKey.Exists (PlatformNotSupportedException): CNG is not supported
            // CngKey.Exists (CryptographicException): all other errors
            catch (Exception)
            {
                return false;
            }

            // If a key exists and TryGetRsaKeyByName() returned false, the key is not usable
            if (tpmKeyExists)
            {
                return false;
            }

            CngKey cngKey;

            string keyCreateDescription = "Encrypting/decrypting account keys, and signing/verifying account records, in LTO Encryption Manager.";
            string keyUseContext = keyCreateDescription;
            CngKeyCreationParameters creationParameters = new()
            {
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
                Provider = tpmCryptoProvider,
                UIPolicy = new(CngUIProtectionLevels.ProtectKey, keyName, keyCreateDescription, keyUseContext),
                KeyCreationOptions = CngKeyCreationOptions.None
            };
            CngProperty keySize;
            try
            {
                keySize = new("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None);
            }
            // CngProperty.ctor (ArgumentNullException): name argument is null
            catch (Exception)
            {
                return false;
            }
            creationParameters.Parameters.Add(keySize);

            try
            {
                cngKey = CngKey.Create(CngAlgorithm.Rsa, keyName, creationParameters);
            }
            // CngKey.Create (ArgumentNullException): algorithm argument is null
            // CngKey.Create (PlatformNotSupportedException): CNG is not supported
            // CngKey.Create (CryptographicException): all other errors
            catch (Exception)
            {
                return false;
            }

            try
            {
                rsaCng = new(cngKey);
            }
            // RsaCng.ctor (ArgumentException): key argument is not an RSA key
            // RSACng.ctor (ArgumentNullException): key argument is null
            catch (Exception)
            {
                return false;
            }

            // Application security policy: Key must be non-exportable
            return rsaCng.Key.ExportPolicy == CngExportPolicies.None;
        }

        /// <summary>
        /// Try to get a valid certificate where all <paramref name="requiredOids"/> are explicitly specified in extended key usages
        /// </summary>
        /// <param name="requiredOids">OIDs for key purposes that a valid certificate must explicitly specify</param>
        /// <param name="certificate">The first valid certificate found, if any</param>
        /// <returns>true on success, otherwise false</returns>
        public static bool TryGetValidCertificate(OidCollection requiredOids, [NotNullWhen(true)] out X509Certificate2? certificate)
        {
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
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Try to get a TPM-backed certificate, or try to create one
        /// </summary>
        /// <param name="certificate">The retrieved or created certificate</param>
        /// <param name="updateSystemOids">Whether system OID database should be updated (true) or not (false)</param>
        /// <returns>true on success, otherwise false</returns>
        public static bool TryGetOrCreateRsaCertificate([NotNullWhen(true)] out X509Certificate2? certificate, bool updateSystemOids = false, bool forceRefreshSystemOids = false)
        {
            certificate = null;

            OidCollection ekuOids = [];
            Oid idKpLtoEncryptionManagerOid = new("1.2.826.0.1.11484356.1.0.0.3.0", "Encrypting/decrypting account keys, and signing/verifying account records, in LTO Encryption Manager");
            ekuOids.Add(idKpLtoEncryptionManagerOid);

            if (updateSystemOids)
            {
                UpdateOidFriendlyNames(ekuOids, forceRefreshSystemOids);
            }

            if (!TryGetOrCreateRsaKey(out RSACng? rsaCng))
            {
                return false;
            }

            if (TryGetValidCertificate(ekuOids, out certificate))
            {
                return true;
            }

            CertificateRequest certificateRequest;
            X500DistinguishedName distinguishedName = new("CN=LTO Encryption Manager", X500DistinguishedNameFlags.None);
            try
            {
                certificateRequest = new(distinguishedName, rsaCng, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            // CertificateRequest.ctor (ArgumentNullException): arguments subjectName and/or key are null
            // CertificateRequest.ctor (ArgumentException): argument hashAlgorithm has a Name that is null or empty
            catch (Exception)
            {
                return false;
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
            catch (Exception)
            {
                return false;
            }
            certificateRequest.CertificateExtensions.Add(enhancedKeyUsageExtension);
            try
            {
                DateTimeOffset notBefore = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
                DateTimeOffset notAfter = DateTimeOffset.UtcNow + TimeSpan.FromDays(90);
                certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);
            }
            // CertificateRequest.CreateSelfSigned (ArgumentException): argument notAfter is earlier than argument notBefore
            // CertificateRequest.CreateSelfSigned (InvalidOperationException): the CertificateRequest.ctor used doesn't accept a signing key
            // CertificateRequest.CreateSelfSigned (CryptographicException): an error occurred creating the certificate
            // CertificateRequest.CreateSelfSigned (ArgumentOutOfRangeException): the CertificateRequest.HashAlgorithm is not supported
            catch (Exception)
            {
                return false;
            }

            certificate.FriendlyName = "LTO Encryption Manager";
            try
            {
                using X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
                my.Open(OpenFlags.ReadWrite);
                my.Add(certificate);
                my.Close();
                return true;
            }
            // X509Store.ctor (ArgumentException): argument storeLocation is not a valid location or argument storeName is not a valid name
            // X509Store.Open (CryptographicException): the store cannot be opened as requested
            // X509Store.Open (SecurityException): the caller does not have the required permission
            // X509Store.Open (ArgumentException): the store contains invalid values
            // X509Store.Add (ArgumentNullException): the certificate argument is null
            // X509Store.Add (CryptographicException): the certificate could not be added to the store
            catch (Exception)
            {
                return false;
            }
        }
    }
}

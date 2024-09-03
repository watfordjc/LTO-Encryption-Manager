using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
	public class KeyAssociatedData
	{
		/// <summary>
		/// The Z85 alphabet as string, usable as a character array for converting numbers to characters
		/// </summary>
		readonly string z85Alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%\\$#";
		/// <summary>
		/// The barcode of an LTO tape
		/// </summary>
		public string TapeBarcode { get; init; }
		/// <summary>
		/// The number of global key rollovers
		/// </summary>
		public uint GlobalKeyRollovers { get; set; }
		/// <summary>
		/// The number of account key rollovers
		/// </summary>
		public uint AccountKeyRollovers { get; set; }
		/// <summary>
		/// The number of tape key rollovers
		/// </summary>
		public uint TapeKeyRollovers { get; set; }
		/// <summary>
		/// The identifier for the key-derivation function's schema
		/// </summary>
		/// <remarks>The default value <c>UKEQ521LTO1</c> means the SLIP-0021 schema <c>uk.johncook.slip-0021.lto-aes256-gcm</c></remarks>
		public string KdfSchema { get; set; } = "UKEQ521LTO1";
		/// <summary>
		/// The account identifier
		/// </summary>
		public string? AccountId { get; init; }
		/// <summary>
		/// The identifier for the key validation scheme
		/// </summary>
		/// <remarks>The default value <c>UKEQ521SKV1</c> means the SLIP-0021 schema <c>uk.johncook.slip-0021.key-validation</c></remarks>
		public string ValidationSchema { get; set; } = "UKEQ521SKV1";
		/// <summary>
		/// The identifier for the hashing schema and its properties
		/// </summary>
		/// <remarks>
		/// <para>The default value <c>:rfc:9160 S4#R1</c> means the hashing algorithm defined in <c>urn:ietf:rfc:9160</c> (RFC 9160) with the parameters defined in <c>S4#R1</c> (Section 4, Recommendation 1).</para>
		/// </remarks>
		public string HashingSchema { get; init; } = ":rfc:9160 S4#R1";
		/// <summary>
		/// The fingerprint for the tape
		/// </summary>
		/// <remarks>
		/// <para></para>
		/// </remarks>
		public string? TapeFingerprint { get; set; }

		/// <summary>
		/// Instantiate an instance of <see cref="KeyAssociatedData"/>
		/// </summary>
		/// <param name="encryptedAccountNode">An instance of <see cref="ImprovementProposals.Models.Slip21NodeEncrypted"/> containing the account details for the account that 'owns' the tape</param>
		/// <param name="tapeBarcode">The barcode of the tape, including the suffix and excluding the start/stop character (e.g. <c>LTO123L6</c>)</param>
		/// <param name="tapeKeyRollovers">The number of times the tape's key has been rolled over</param>
		/// <param name="tapeFingerprint">The optional fingerprint of the tape (default is <c>null</c> as it may not be known at time of instantiation)</param>
		/// <remarks>
		/// <para>If <paramref name="tapeFingerprint"/> is <c>null</c>, ensure <see cref="TapeFingerprint"/> is set before calling <see cref="GetKAD(string?)"/>.</para>
		/// </remarks>
		public KeyAssociatedData(ImprovementProposals.Models.Slip21NodeEncrypted encryptedAccountNode, string tapeBarcode, uint tapeKeyRollovers, string? tapeFingerprint = null)
		{
			ArgumentNullException.ThrowIfNull(encryptedAccountNode);
			Debug.Assert(HashingSchema.Count(x => x.Equals(' ')) <= 1, $"{nameof(HashingSchema)} contains more than one space character");
			TapeBarcode = tapeBarcode;
			GlobalKeyRollovers = encryptedAccountNode.GlobalKeyRolloverCount;
			AccountId = encryptedAccountNode.AccountLabel;
			TapeKeyRollovers = tapeKeyRollovers;
			TapeFingerprint = tapeFingerprint;
		}

		/// <summary>
		/// Get the Key-Authenticated Data (KAD) for the tape
		/// </summary>
		/// <param name="accountIdMdfHash">The Modular Crypt Format (MCF) hash of the <see cref="AccountId"/>. A value of <c>null</c> (the default) encodes the <see cref="AccountId"/> per <c>uk.johncook.slip-0021.lto-aes256-gcm</c>.</param>
		/// <returns>
		/// The Key-Authenticated Data (KAD) for the tape
		/// </returns>
		/// <remarks>
		/// <para>This method <b>does not</b> calculate <see cref="TapeFingerprint"/>.</para>
		/// <para><c>if (<paramref name="accountIdMdfHash"/> is null)</c>, the <see cref="AccountId"/> is hashed using the method defined in <c>uk.johncook.slip-0021.lto-aes256-gcm</c> (i.e. the Z85-encoded CRC32 of the <see cref="AccountId"/>).</para>
		/// <para><c>if (<paramref name="accountIdMdfHash"/> is not null &amp;&amp; <paramref name="accountIdMdfHash"/>.StartsWith('$'))</c>, <paramref name="accountIdMdfHash"/> is used as the hash representing the <see cref="AccountId"/>.</para>
		/// <para><c>if (<paramref name="accountIdMdfHash"/> is not null &amp;&amp; !<paramref name="accountIdMdfHash"/>.StartsWith('$'))</c>, <paramref name="accountIdMdfHash"/> is translated per <c>uk.johncook.slip-0021.lto-aes256-gcm</c> for representing the <see cref="AccountId"/>.</para>
		/// </remarks>
		public string GetKAD(string? accountIdMdfHash = null)
		{
			{
				StringBuilder sb = new();
				_ = sb.Append(TapeBarcode); // Cartridge Barcode field
				_ = sb.Append('*'); // Cartridge Barcode field terminator
				_ = sb.Append(z85Alphabet[(int)GlobalKeyRollovers % 85]); // Keys Rollover field start
				_ = sb.Append(z85Alphabet[(int)AccountKeyRollovers % 85]);
				_ = sb.Append(z85Alphabet[(int)TapeKeyRollovers % 85]);
				_ = sb.Append('*'); // Keys Rollover field terminator
				_ = sb.Append(KdfSchema); // Key Derivation Schema/Standard Reference field
				_ = sb.Append('*'); // Key Derivation Schema/Standard Reference field terminator
									// If the default Account Identifier field encoding/hashing is not to be used:
				if (accountIdMdfHash is not null)
				{
					/*
					 * Most MDF hashes start with a $ and an algorithm identifier (Scheme ID), such as $6 for SHA2-512.
					 * For those that don't, uk.johncook.slip-0021.lto-aes256-gcm defines custom MDF scheme ids that are incompatible with the Public Hashing Competition String Format.
					 * The PHC String Format is the successor to MDF, with the id field (function symbolic name) character set restricted to [a-z0-9-].
					 * 
					 * Two known MDF scheme ids that are incompatible with the PHC String Format are '' (none, for DES), and '_' (underscore, for BSDi).
					 * The schema uk.johncook.slip-0021.lto-aes256-gcm translates these so they start with a $ symbol:
					 *   * '' (DES) gets the function symbolic name ' ' (ASCII space), so a DES accountIdMdfHash becomes ('$ ' + accountIdMdfHash)
					 *   * '_' (BSDi) gets the function symbolic name '_' (ASCII underscore) so a BSDi accountIdMdfHash becomes ('$_' + accountIdMdfHash)
					 */
					// If the MCF hash is not PHC compatible (i.e. doesn't start with $<id>), it needs translating:
					if (!accountIdMdfHash.StartsWith('$'))
					{
						_ = sb.Append('$'); // Prepend a '$'
						if (!accountIdMdfHash.StartsWith('_')) // Only DES needs additional treatment
						{
							_ = sb.Append(' '); // Prepend a ' ' for DES
						}
					}
					_ = sb.Append(accountIdMdfHash); // Append the MCF hash
				}
				// By default, the Account Identifier field in the KAD is the Z85-encoded CRC32 of the Account Identifier per uk.johncook.slip-0021.lto-aes256-gcm.
				// This is done for several reasons, such as making any PII in the Account Identifier pseudonymous and due to LTO KAD length restrictions.
				// If a future version of LTO expands the character limit of the KAD field again, MDF/PHC could be used without a change to the specification (or this method).
				else
				{
					// Convert the Account ID ASCII string ("0" for the primary account) to a byte array
					byte[] accountIdBytes = Encoding.ASCII.GetBytes(AccountId ?? "0");
					Algorithms.Crc32 crc32 = new();
					// Calculate the CRC32 of the Account ID
					if (crc32.TryGet(accountIdBytes, out uint? accountIdCrc32))
					{
						// Convert the CRC32 uint to a byte array
						byte[] accountIdCrc32Bytes = BitConverter.GetBytes((uint)accountIdCrc32);
						// Make the CRC32 byte array Big Endian byte order for Z85 encoding
						if (BitConverter.IsLittleEndian)
						{
							Array.Reverse(accountIdCrc32Bytes);
						}
						// Conver the CRC32 to Z85-encoding
						if (Encodings.TryGetToZ85Encoded(accountIdCrc32Bytes, out byte[]? accountIdZ85))
						{
							_ = sb.Append(Encoding.ASCII.GetString(accountIdZ85)); // Append the Account Identifier hash (Z85-encoded CRC32)
						}
					}
				}
				_ = sb.Append(' '); // Account Identifier field terminator
				_ = sb.Append(ValidationSchema); // Key Validation Schema/Standard field
				_ = sb.Append(':'); // Key Validation Schema/Standard field terminator
				_ = sb.Append(HashingSchema); // Hashing Algorithm and Parameters Schema/Standard Reference field
											  // The Hashing Algorithm and Parameters Schema/Standard Reference field contains up to two space-separated values
				if (!HashingSchema.Contains(' ', System.StringComparison.Ordinal))
				{
					_ = sb.Append(' '); // The Hashing Algorithm and Parameters Schema/Standard Reference field must be padded with a space character if it doesn't contain a space character
				}
				_ = sb.Append(' '); // Hashing Algorithm and Parameters Schema/Standard Reference field terminator
				_ = sb.Append(TapeFingerprint); // Tape Key Validation Fingerprint field
				_ = sb.Append(' '); // Tape Key Validation Fingerprint field terminator
				return sb.ToString();
			}
		}
	}
}

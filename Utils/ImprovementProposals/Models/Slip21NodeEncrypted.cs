using System.Collections.ObjectModel;
using System.Text;
using System.Text.RegularExpressions;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models
{
	public partial class Slip21NodeEncrypted
	{
		[GeneratedRegex("(?:^|/)(?:\")((?:[^\"])*|[^/]*)(?:\")")]
		private static partial Regex DerivationPathRegex();
		/// <summary>
		/// The left 32 bytes of the node (the derivation key), encrypted with RSA key and encoded as a hexadecimal string
		/// </summary>
		public string EncryptedLeftHex { get; }
		/// <summary>
		/// The derivation path of the node encoded as a UTF-8 string
		/// </summary>
		public string DerivationPath { get; init; }
		/// <summary>
		/// The global key rollover count value encoded as a UTF-8 string (i.e. "0" = 0)
		/// </summary>
		public uint GlobalKeyRolloverCount { get; init; }
		/// <summary>
		/// The Z85-encoded fingerprint of the global key rollover node, encoded as a UTF-8 string (i.e. a=a)
		/// </summary>
		public string? GlobalFingerprint { get; set; }
		/// <summary>
		/// The Z85-encoded fingerprint of the account key rollover node, encoded as a UTF-8 string (i.e. a=a)
		/// </summary>
		public string? AccountFingerprint { get; set; }
		/// <summary>
		/// A UTF-8 string that combines the above properties into a string that can be signed using PKI (i.e. signed using an RSA private key)
		/// </summary>
		public string SignablePart
		{
			get
			{
				StringBuilder sb = new();
				sb.Append(EncryptedLeftHex).Append('\x001F').Append(DerivationPath).Append('\x001F').Append(GlobalKeyRolloverCount);
				if (GlobalFingerprint != null)
				{
					sb.Append('\x001F').Append(GlobalFingerprint);
				}
				if (AccountFingerprint != null)
				{
					sb.Append('\x001F').Append(AccountFingerprint);
				}
				return sb.ToString();
			}
		}
		/// <summary>
		/// An RSA signature for the value of <see cref="SignablePart"/>, encoded as a hexadecimal string
		/// </summary>
		public string? RSASignature { get; set; }

		public Collection<string> NodeLabels { get; init; } = [];
		public string? FirstLevelLabel => NodeLabels.Count > 0 ? NodeLabels[0] : null;
		public uint? GlobalRolloverCountLabel => NodeLabels.Count > 1 && uint.TryParse(NodeLabels[1], out uint count) ? count : null;
		public string? AccountLabel => NodeLabels.Count > 2 ? NodeLabels[2] : null;
		public uint? AccountRolloverCountLabel => NodeLabels.Count > 3 && uint.TryParse(NodeLabels[3], out uint count) ? count : null;

		public Slip21NodeEncrypted(string encryptedLeftHex, string derivationPath, string globalKeyRolloverCount)
		{
			EncryptedLeftHex = encryptedLeftHex;
			DerivationPath = derivationPath;
			if (uint.TryParse(globalKeyRolloverCount, out uint count))
			{
				GlobalKeyRolloverCount = count;
			}
			string? currentPart;
			foreach (Match match in DerivationPathRegex().Matches(derivationPath))
			{
				currentPart = match.Groups[1].Value;
				if (0 == currentPart.Length)
				{
					NodeLabels.Add("");
				}
				NodeLabels.Add(currentPart.TrimStart('/'));
			}
		}
	}
}

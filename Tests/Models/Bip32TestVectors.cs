﻿using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json.Serialization;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Bip32TestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public Collection<Bip32TestVector>? Vectors { get; init; }
	}

	public class Bip32TestVector : Collection<string>
	{
		public string CurveName => this[0];
		public string PublicKeyPrefix => this[1];
		public uint? PublicKeyPrefixValue => Bip32.GetHostUInt32FromNetworkBytes(Convert.FromHexString(PublicKeyPrefix));
		public string PrivateKeyPrefix => this[2];
		public uint? PrivateKeyPrefixValue => Bip32.GetHostUInt32FromNetworkBytes(Convert.FromHexString(PrivateKeyPrefix));
		public string MnemonicBinarySeed => this[3];
		public string ParentPrivateKey => this[4];
		public string ParentDerivationPath => this[5];
		public string IndexString => this[6];
		public bool IsHardenedChild => IndexString.EndsWith('H');
		public uint Index
		{
			get
			{
				return IsHardenedChild ? uint.Parse(IndexString[..^1], NumberStyles.None, CultureInfo.InvariantCulture) ^ 0x8000_0000 : uint.Parse(IndexString, NumberStyles.None, CultureInfo.InvariantCulture);
			}
		}
		public string DerivationPath => ParentDerivationPath.Length == 0 && IndexString.Length == 0 ? "m" : string.Format(CultureInfo.InvariantCulture, "{0}/{1}", ParentDerivationPath, IndexString);
		public string PublicKey => this[7];
		public string PrivateKey => this[8];
	}
}

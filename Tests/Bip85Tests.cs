using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
	[TestClass]
	public class Bip85Tests
	{
		public static async Task<Collection<Models.Bip85EntropyFromKTestVector>?> GetEntropyFromKTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/bip0085-entropy-from-k-vectors.json");
			Models.Bip85EntropyFromKTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip85EntropyFromKTestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.Vectors;
		}

		public static Bip32Node GetBip32RootNode(string masterNodePrivateKey)
		{
			Bip32Node rootNode = new(masterNodePrivateKey, null);
			Assert.IsNotNull(rootNode);
			Assert.IsTrue(rootNode.IsInitialised);
			Assert.IsNotNull(rootNode.VersionPrefixPrivate);
			return rootNode;
		}

		public static Bip32Node? GetBip32NodeFromDerivationPath(Bip32Node rootNode, string derivationPath)
		{
			Assert.IsNotNull(rootNode);
			Assert.IsNotNull(derivationPath);
			Assert.IsTrue(rootNode.IsInitialised);
			Assert.IsNotNull(rootNode.VersionPrefixPrivate);

			uint versionBytesPrivate = (uint)rootNode.VersionPrefixPrivate;
			ECDomainParameters? domainParams = Bip32.GetDomainParameters(versionBytesPrivate);
			Assert.IsNotNull(domainParams);
			string[] derivationPathSplits = derivationPath.Split('/', StringSplitOptions.None);
			Bip32Node? derivationNode = rootNode;
			foreach (string indexString in derivationPathSplits)
			{
				if (indexString == "m")
				{
					continue;
				}
				uint childIndex = indexString.EndsWith('H') ? uint.Parse(indexString[..^1], NumberStyles.None, CultureInfo.InvariantCulture) ^ 0x8000_0000 : uint.Parse(indexString, NumberStyles.None, CultureInfo.InvariantCulture);
				Bip32Node? currentChildNode = Bip32Node.GetChildNode(domainParams, ref derivationNode, childIndex);
				Assert.IsNotNull(currentChildNode);
				Assert.IsTrue(currentChildNode.IsInitialised);
				derivationNode = currentChildNode;
			}
			return derivationNode;
		}

		[TestMethod]
		public async Task GetEntropyFromKTest()
		{
			IEnumerable<Models.Bip85EntropyFromKTestVector>? testVectors = await GetEntropyFromKTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node rootNode = GetBip32RootNode(testVector.MasterNodePrivateKey);
				Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, testVector.DerivationPath);
				Assert.IsNotNull(derivationNode);
				Assert.IsFalse(derivationNode.IsMasterNode);
				Assert.AreEqual(testVector.DerivationPath, derivationNode.DerivationPath);
				Assert.IsNotNull(derivationNode.PrivateKeySerialised);
				Assert.AreEqual(testVector.PrivateKeyHex, new(Utils.Encodings.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, Utils.Encodings.ToHexString([.. entropyFromK]));
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}
	}
}

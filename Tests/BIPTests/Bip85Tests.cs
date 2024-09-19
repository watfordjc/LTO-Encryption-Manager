using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.BIPTests
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
		public static async Task<Collection<Models.Bip85DrngEntropyTestVector>?> GetDrngEntropyTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/bip0085-drng-entropy-shake256-vectors.json");
			Models.Bip85DrngEntropyTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip85DrngEntropyTestVectorsRoot>(openStream).ConfigureAwait(false);
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
				Assert.AreEqual(testVector.PrivateKeyHex, new(Utils.ByteEncoding.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, Utils.ByteEncoding.ToHexString([.. entropyFromK]));
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public async Task GetDrngEntropyTest()
		{
			IEnumerable<Models.Bip85DrngEntropyTestVector>? testVectors = await GetDrngEntropyTestVectorsAsync().ConfigureAwait(false);
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
				Assert.AreEqual(testVector.PrivateKeyHex, new(Utils.ByteEncoding.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, Utils.ByteEncoding.ToHexString([.. entropyFromK]));
				ReadOnlySpan<byte> drngEntropy = Bip85.GetShake256Entropy(derivationNode, testVector.RequestedEntropyBytes);
				Assert.AreEqual(testVector.DrngEntropyHex, Utils.ByteEncoding.ToHexString([.. drngEntropy]));
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public void GetBip39EntropyTest()
		{
			Bip32Node rootNode = GetBip32RootNode("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");

			Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/12H/0H");
			Assert.IsNotNull(derivationNode);
			string entropyResult = ByteEncoding.ToHexString(Bip85.GetBip39Entropy(derivationNode));
			Assert.AreEqual("6250b68daf746d12a24d58b4787a714b".ToUpperInvariant(), entropyResult);

			derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/18H/0H");
			Assert.IsNotNull(derivationNode);
			entropyResult = ByteEncoding.ToHexString(Bip85.GetBip39Entropy(derivationNode));
			Assert.AreEqual("938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc".ToUpperInvariant(), entropyResult);

			derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/24H/0H");
			Assert.IsNotNull(derivationNode);
			entropyResult = ByteEncoding.ToHexString(Bip85.GetBip39Entropy(derivationNode));
			Assert.AreEqual("ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f".ToUpperInvariant(), entropyResult);
		}

		[TestMethod]
		public void GetBip39SeedPhraseTest()
		{
			Bip32Node rootNode = GetBip32RootNode("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");

			Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/12H/0H");
			Assert.IsNotNull(derivationNode);
			string seedPhraseResult = Bip85.GetBip39Words(derivationNode);
			Assert.AreEqual("girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", seedPhraseResult);

			derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/18H/0H");
			Assert.IsNotNull(derivationNode);
			seedPhraseResult = Bip85.GetBip39Words(derivationNode);
			Assert.AreEqual("near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token", seedPhraseResult);

			derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/39H/0H/24H/0H");
			Assert.IsNotNull(derivationNode);
			seedPhraseResult = Bip85.GetBip39Words(derivationNode);
			Assert.AreEqual("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano", seedPhraseResult);
		}

		[TestMethod]
		public void GetXprvTest()
		{
			Bip32Node rootNode = GetBip32RootNode("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");
			Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/32H/0H");
			Assert.IsNotNull(derivationNode);
			Bip32Node? derivedXprvNode = Bip85.GetXprv(derivationNode);
			Assert.IsNotNull(derivedXprvNode);
			Assert.AreEqual("xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX",
				derivedXprvNode.PrivateKeySerialised);
		}

		[TestMethod]
		public void GetHextest()
		{
			Bip32Node rootNode = GetBip32RootNode("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");
			Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/128169H/64H/0H");
			Assert.IsNotNull(derivationNode);
			string result = Bip85.GetHex(derivationNode);
			Assert.AreEqual("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c".ToUpperInvariant(),
				result);
		}

		[TestMethod]
		public async Task GetRSATest()
		{
			IEnumerable<Models.Bip85DrngEntropyTestVector>? testVectors = await GetDrngEntropyTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node rootNode = GetBip32RootNode(testVector.MasterNodePrivateKey);
				Bip32Node? derivationNode = GetBip32NodeFromDerivationPath(rootNode, "m/83696968H/828365H/3072H/0H");
				Assert.IsNotNull(derivationNode);
				Assert.IsTrue(Bip85.TryCreateStandardRSA(derivationNode, Utils.Algorithms.StandardRSA.Compatibility.BIP85, out RSA? rsaKey));
				Assert.IsNotNull(rsaKey);
				Assert.AreEqual(3072, rsaKey.KeySize);
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public async Task GetDrngEntropyStreamTest()
		{
			IEnumerable<Models.Bip85DrngEntropyTestVector>? testVectors = await GetDrngEntropyTestVectorsAsync().ConfigureAwait(false);
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
				Assert.AreEqual(testVector.PrivateKeyHex, new(Utils.ByteEncoding.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, Utils.ByteEncoding.ToHexString([.. entropyFromK]));

				using Shake256DRNG shake256DRNG = new(derivationNode);
				using Shake256Stream shake256Stream = new(shake256DRNG);
				byte[] drngEntropy = new byte[80];
				// Read 10 bytes into drngEntropy[0..]
				shake256Stream.Read(drngEntropy, 0, 10);
				// Read 40 bytes into drngEntropy[10..]
				shake256Stream.Read(drngEntropy, 10, 40);
				// Read 30 bytes into drngEntropy[50..]
				shake256Stream.Read(drngEntropy, 50, 30);
				Assert.AreEqual(testVector.DrngEntropyHex, Utils.ByteEncoding.ToHexString(drngEntropy));
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}


		[TestMethod]
		public async Task ExtendedDeterminismTest()
		{
			IEnumerable<Models.Bip85DrngEntropyTestVector>? testVectors = await GetDrngEntropyTestVectorsAsync().ConfigureAwait(false);
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
				Assert.AreEqual(testVector.PrivateKeyHex, new(Utils.ByteEncoding.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, Utils.ByteEncoding.ToHexString([.. entropyFromK]));

				using Shake256DRNG shake256DRNG = new(derivationNode);
				using Shake256Stream shake256Stream = new(shake256DRNG);
				shake256Stream.SetStreamLength(0);
				using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
				int bufferSize = 32768;
				byte[] buffer = new byte[bufferSize];
				// Test for 1 KiB, 1 MiB, 5 MiB, 1 GiB
				long[] bytesToCheckArray = [
					80,
					1 * (1 << 10),
					1 * (1 << 20),
					5 * (1 << 20),
					1 * (1 << 30)
					];
				string[] expectedHashes = [
					testVector.DrngEntropy80BSha512Hash,
					testVector.DrngEntropy1KiBSha512Hash,
					testVector.DrngEntropy1MiBSha512Hash,
					testVector.DrngEntropy5MiBSha512Hash,
					testVector.DrngEntropy1GiBSha512Hash
					];
				Assert.AreEqual(bytesToCheckArray.Length, expectedHashes.Length);

				for (int i = 0; i < bytesToCheckArray.Length; i++)
				{
					long bytesToCheck = bytesToCheckArray[i];
					string expectedHash = expectedHashes[i];
					try
					{
						long startPosition = shake256Stream.Position;
						long stillToRead = bytesToCheck;
						CancellationToken token = new(false);
						Assert.IsTrue(shake256Stream.CanRead);
						shake256Stream.ExtendStreamLength(bytesToCheck);
						Assert.IsTrue(shake256Stream.Position < shake256Stream.Length);
						while (stillToRead > 0)
						{
							Assert.IsTrue(shake256Stream.CanRead);
							Assert.IsTrue(shake256Stream.Position < shake256Stream.Length);
							int bytesToRead = stillToRead > bufferSize ? bufferSize : (int)stillToRead;
							int bytesRead = shake256Stream.Read(buffer, 0, bytesToRead);
							hasher.AppendData(buffer, 0, bytesRead);
							stillToRead -= bytesRead;
						}
						byte[] hash = new byte[SHA512.HashSizeInBytes];
						hasher.GetHashAndReset(hash);
						Assert.AreEqual(shake256Stream.Length, shake256Stream.Position);
						string hashString = Utils.ByteEncoding.ToHexString(hash);
						Assert.AreEqual(expectedHash, hashString);
						Trace.WriteLine($"Path: {testVector.DerivationPath}, byte[{startPosition}..{shake256Stream.Position}] ({bytesToCheck} bytes wanted from DRNG), SHA2-512 Hash: {hashString}");
					}
					catch (Exception)
					{
						throw;
					}
				}

				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}
	}
}

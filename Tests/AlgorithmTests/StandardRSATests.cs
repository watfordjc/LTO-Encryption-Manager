using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Tests.BIPTests;
using uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;
using static uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Bip85;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.AlgorithmTests
{
	[TestClass]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Ordered tests need numbering")]
    public class StandardRSATests
    {
        /// <summary>
        /// Creates a <see cref="Collection{T}"/> of <see cref="RsaTestVector"/>.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        public static async Task<Collection<RsaTestVector>?> GetRsaTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/rsa-test-vectors.json");
            RsaTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<RsaTestVectorsRoot>(openStream).ConfigureAwait(false);
            openStream.Close();
            return jsonRoot?.Vectors;
        }

        /// <summary>
        /// A test to double-check RSA parameter 'e' (which should be a constant) is 65,537.
        /// </summary>
        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code", Justification = "Constant Bip85.RSAParameterE must always equal 65537, even if the source code is changed.")]
        public void Test001_RSAConstantEEquals65537()
        {
            Trace.WriteLine($"RSA Constant for e ({nameof(StandardRSA.ParameterE)}): {StandardRSA.ParameterE}");
            Assert.IsTrue(StandardRSA.ParameterE == 65537);
        }

        /// <summary>
        /// A test to verify PEM-encoding of <see cref="RsaTestVector"/> values.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test002_PemCreation()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);

            Parallel.For(0, testVectors.Count, i =>
            {
                RSAParameters rsaParameters = new()
                {
                    Modulus = [.. testVectors[i].Modulus],
                    Exponent = [.. testVectors[i].PublicExponent],
                    D = [.. testVectors[i].PrivateExponent],
                    P = [.. testVectors[i].Prime1],
                    Q = [.. testVectors[i].Prime2],
                    DP = [.. testVectors[i].Exponent1],
                    DQ = [.. testVectors[i].Exponent2],
                    InverseQ = [.. testVectors[i].Coefficient]
                };
                string pem = CreatePem(rsaParameters);
                string hashsum = ByteEncoding.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pem)));
                Trace.WriteLine($"Result for index {i}: {hashsum}");
                Assert.AreEqual(testVectors[i].PemSha256HashString, hashsum);
                Trace.WriteLine($"Test for index {i} successful.");
            });
        }

        /// <summary>
        /// A test to verify <see cref="RSAParameters"/> creation from <see cref="RsaTestVector.Prime1"/> and <see cref="RsaTestVector.Prime2"/>.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test003_PrimesToRsaParameters()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);

            Parallel.For(0, testVectors.Count, i =>
            {
                BigPrime p = new(new BigInteger(testVectors[i].Prime1, true, true), StandardRSA.Compatibility.None);
                BigPrime q = new(new BigInteger(testVectors[i].Prime2, true, true), StandardRSA.Compatibility.None);
                int publicModulusBitLength = testVectors[i].Modulus.Length * 8;
                RSAParameters? rsaParameters = StandardRSA.GetRSAParametersForPrimes(p, q, publicModulusBitLength);
                Assert.IsNotNull(rsaParameters);
                string pem = CreatePem(rsaParameters.Value);
                string hashsum = ByteEncoding.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pem)));
                Trace.WriteLine($"Result for index {i}: {hashsum}");
                Assert.AreEqual(testVectors[i].PemSha256HashString, hashsum);
                Trace.WriteLine($"Test for index {i} successful.");
            });
        }

        /// <summary>
        /// A test to verify <see cref="Bip85.GetEntropy(Bip32Node, int)"/> from <see cref="RsaTestVector.MasterNodePrivateKey"/> and
        ///   <see cref="RsaTestVector.DerivationPath"/>.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test004_EntropyFromSerialisedKey()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);

            Parallel.For(0, testVectors.Count, i =>
            {
                Bip32Node? rootNode = Bip32.GetMasterNodeFromSerialisedPrivateKey(testVectors[i].MasterNodePrivateKey);
                Assert.IsNotNull(rootNode);
                Bip32Node? derivationNode = Bip85Tests.GetBip32NodeFromDerivationPath(rootNode, testVectors[i].DerivationPath);
                Assert.IsNotNull(derivationNode);
                Assert.IsFalse(derivationNode.IsMasterNode);
                Assert.IsNotNull(derivationNode.PrivateKeySerialised);
                ReadOnlySpan<byte> entropyFromK = GetEntropy(derivationNode, 64).ToArray();
                string entropyFromKString = ByteEncoding.ToHexString(entropyFromK);
                Assert.AreEqual(testVectors[i].EntropyHex, entropyFromKString);
            });
        }

        /// <summary>
        /// A test to verify <see cref="Shake256DRNG"/> determinism from <see cref="RsaTestVector.EntropyHex"/>.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test005_DeterministicBytesFromEntropy()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);

            Parallel.For(0, testVectors.Count, i =>
            {
                if (testVectors[i].Shake256Output1.IsEmpty || testVectors[i].Shake256Output2.IsEmpty)
                {
                    return;
                }

                using Shake256DRNG shake256DRNG = new(ByteEncoding.FromHexString(testVectors[i].EntropyHex));
                Span<byte> shake256Output1 = new byte[testVectors[i].Shake256Output1.Length];
                shake256DRNG.GetBytes(shake256Output1);
                Assert.IsTrue(shake256Output1.SequenceEqual(testVectors[i].Shake256Output1));
                Span<byte> shake256Output2 = new byte[testVectors[i].Shake256Output2.Length];
                shake256DRNG.GetBytes(shake256Output2);
                Assert.IsTrue(shake256Output2.SequenceEqual(testVectors[i].Shake256Output2));
            });
        }

        /// <summary>
        /// A test to verify the searching of two prime numbers whose product is a modulus with the correct byte length.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test006_PrimesFromEntropyProductSize()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            using SemaphoreSlim semaphoreSlim = new(1);
            Parallel.For(0, testVectors.Count, i =>
            {
                if (Debugger.IsAttached)
                {
                    semaphoreSlim.Wait();
                }
                ReadOnlySpan<byte> entropy = ByteEncoding.FromHexString(testVectors[i].EntropyHex);
                Assert.IsFalse(entropy.IsEmpty);
                Assert.AreEqual(64, entropy.Length);
                // Convert modulus byte length to bits and halve for prime length in bits
                int primeLength = testVectors[i].Modulus.Length * 4;

                using Shake256DRNG shake256DRNG = new(entropy);

                BigPrime candidate1 = BigPrime.Create(primeLength, StandardRSA.Compatibility.BIP85, shake256DRNG, StandardRSA.CandidatePCallback);
                bool qCallback(BigInteger candidateQ, int bitLength)
                {
                    return StandardRSA.CandidateQCallback(candidateQ, candidate1, primeLength);
                }
                BigPrime candidate2 = BigPrime.Create(primeLength, StandardRSA.Compatibility.BIP85, shake256DRNG, qCallback);

                BigInteger n = candidate1 * candidate2;
                BigInteger publicModulus = new(testVectors[i].Modulus, true, true);
                Assert.AreEqual(publicModulus.GetByteCount(true), n.GetByteCount(true));
				if (Debugger.IsAttached)
				{
					semaphoreSlim.Release();
				}
			});
        }

        /// <summary>
        /// A test to verify the primes found in a <see cref="Shake256DRNG"/> seeded from <see cref="RsaTestVector.EntropyHex"/> have a product equal to
        ///   <see cref="RsaTestVector.Modulus"/>.
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test007_PrimesFromEntropy()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphoreSlim = new(1);

			Parallel.For(0, testVectors.Count, i =>
			{
				if (Debugger.IsAttached)
				{
					semaphoreSlim.Wait();
				}
				ReadOnlySpan<byte> entropy = ByteEncoding.FromHexString(testVectors[i].EntropyHex);
                Assert.IsFalse(entropy.IsEmpty);
                Assert.AreEqual(64, entropy.Length);

                // Convert modulus byte length to bits
                int modulusBitLength = testVectors[i].Modulus.Length * 8;
                // Calculate prime length based on modulus length
                int primeBitLength = modulusBitLength / 2;

                using Shake256DRNG shake256DRNG = new(entropy);

                BigPrime? candidateP = null;
                BigPrime? candidateQ = null;
				BigInteger n = 0;

				while (n.GetBitLength() != modulusBitLength)
                {
                    candidateP = BigPrime.Create(primeBitLength, StandardRSA.Compatibility.BIP85, shake256DRNG, StandardRSA.CandidatePCallback);
                    bool qCallback(BigInteger candidateQ, int bitLength)
                    {
                        return StandardRSA.CandidateQCallback(candidateQ, candidateP, primeBitLength);
                    }
                    candidateQ = BigPrime.Create(primeBitLength, StandardRSA.Compatibility.BIP85, shake256DRNG, qCallback);
                    RSAParameters? rsaParams = StandardRSA.GetRSAParametersForPrimes(candidateP, candidateQ, modulusBitLength);
					if (rsaParams is not null && rsaParams.Value.Modulus is not null)
                    {
                        n = new(rsaParams.Value.Modulus, true, true);
                    }
				}

                BigInteger publicModulus = new(testVectors[i].Modulus, true, true);
                Assert.AreEqual(publicModulus.GetByteCount(true), n.GetByteCount(true));
                Assert.AreEqual(publicModulus, n);
				if (Debugger.IsAttached)
				{
					semaphoreSlim.Release();
				}
			});
        }

        /// <summary>
        /// A test to verify PEM creation from <see cref="RsaTestVector.MasterNodePrivateKey"/> (i.e. BIP32 master node, BIP85 node from derivation path, BIP85
        ///   bip-entropy-from-k to seed a <see cref="Shake256DRNG"/>, the finding of primes, the calculation of RSA parameters, and verifying the hash of the
        ///   PEM-encoded private key).
        /// </summary>
        /// <returns>A <see cref="Task"/>.</returns>
        [TestMethod]
        public async Task Test008_PemFromSerialisedKey()
        {
            Collection<RsaTestVector>? testVectors = await GetRsaTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);

            Parallel.For(0, testVectors.Count, i =>
            {
                Bip32Node? rootNode = Bip32.GetMasterNodeFromSerialisedPrivateKey(testVectors[i].MasterNodePrivateKey);
                Assert.IsNotNull(rootNode);
                Bip32Node? derivationNode = Bip85Tests.GetBip32NodeFromDerivationPath(rootNode, testVectors[i].DerivationPath);
                Assert.IsNotNull(derivationNode);
                Assert.IsFalse(derivationNode.IsMasterNode);
                Assert.IsNotNull(derivationNode.PrivateKeySerialised);
                ReadOnlySpan<byte> entropyFromK = GetEntropy(derivationNode, 64).ToArray();
                string entropyFromKString = ByteEncoding.ToHexString(entropyFromK);
                Assert.AreEqual(testVectors[i].EntropyHex, entropyFromKString);

                string privateKeyHash = TestRSAKey(derivationNode, testVectors[i].Modulus.Length * 8, StandardRSA.Compatibility.BIP85);
                Assert.AreEqual(testVectors[i].PemSha256HashString, privateKeyHash);
            });
        }

        private static string CreatePem(RSAParameters rsaParams)
        {
            ArgumentNullException.ThrowIfNull(rsaParams);
            BigInteger p = new(rsaParams.P, true, true);
            BigInteger pMinusOne = p - 1;
            BigInteger q = new(rsaParams.Q, true, true);
            BigInteger qMinusOne = q - 1;
            BigInteger gcdN = BigInteger.GreatestCommonDivisor(pMinusOne, qMinusOne);
            BigInteger phiN = pMinusOne * qMinusOne;
            BigInteger lambdaN = phiN / gcdN;
            BigInteger publicExponent = new(rsaParams.Exponent, true, true);
            BigInteger privateModulus = BigIntegerExtensions.ModInverse(publicExponent, lambdaN);
            Assert.IsNotNull(rsaParams.D);

            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteInteger(0);
            writer.WriteIntegerUnsigned(rsaParams.Modulus);
            writer.WriteIntegerUnsigned(rsaParams.Exponent);
            writer.WriteIntegerUnsigned(privateModulus.ToByteArray(true, true));
            writer.WriteIntegerUnsigned(rsaParams.P);
            writer.WriteIntegerUnsigned(rsaParams.Q);
            writer.WriteIntegerUnsigned(rsaParams.DP);
            writer.WriteIntegerUnsigned(rsaParams.DQ);
            writer.WriteIntegerUnsigned(rsaParams.InverseQ);
            writer.PopSequence();

            StringBuilder sb = new();
            sb.Append("-----BEGIN RSA PRIVATE KEY-----");
            string base64Data = Convert.ToBase64String(writer.Encode());
            const int pemLineWidth = 64;
            int remainder = base64Data.Length % pemLineWidth;
            int startOfRemainder = base64Data.Length - remainder;
            for (int i = 0; i < startOfRemainder; i += pemLineWidth)
            {
                sb.Append('\n');
                sb.Append(base64Data.AsSpan(i, pemLineWidth));
            }
            if (remainder > 0)
            {
                sb.Append('\n');
                sb.Append(base64Data.AsSpan(startOfRemainder));
            }
            sb.Append("\n-----END RSA PRIVATE KEY-----");

            // Encode as PEM
            return sb.ToString();
        }

        private static string TestRSAKey(Bip32Node derivationNode, int keyLength, StandardRSA.Compatibility compatibilityFlags)
        {
            using RSACryptoServiceProvider rSACryptoServiceProvider = new();
            KeySizes[] legalKeySizes = rSACryptoServiceProvider.LegalKeySizes;
            Assert.IsTrue(keyLength >= legalKeySizes[0].MinSize);
            Assert.IsTrue(keyLength <= legalKeySizes[0].MaxSize);
            Assert.IsTrue(keyLength % legalKeySizes[0].SkipSize == 0);
            using Shake256DRNG shake256DRNG = new(derivationNode);
            RSAParameters? rsaParameters = StandardRSA.CreateStandardRSAParameters(keyLength, compatibilityFlags, shake256DRNG);
            Assert.IsNotNull(rsaParameters);
            BigInteger e = new(rsaParameters.Value.Exponent, true, true);
            BigPrime p = new(new BigInteger(rsaParameters.Value.P, true, true), StandardRSA.Compatibility.Default);
            BigPrime q = new(new BigInteger(rsaParameters.Value.Q, true, true), StandardRSA.Compatibility.Default);
            BigInteger n = new(rsaParameters.Value.Modulus, true, true);
            BigInteger d = new(rsaParameters.Value.D, true, true);
            BigInteger dp = new(rsaParameters.Value.DP, true, true);
            BigInteger dq = new(rsaParameters.Value.DQ, true, true);
            BigInteger inverseQ = new(rsaParameters.Value.InverseQ, true, true);

            // P
            Assert.IsTrue(p.IsOdd);
            Assert.AreEqual(keyLength / 2, p.BitLength);
            Assert.IsTrue(p.CheckPrimality(StandardRSA.Compatibility.Default), null);

            // Q
            Assert.IsTrue(q.IsOdd);
            Assert.AreEqual(keyLength / 2, q.BitLength);
            Assert.IsTrue(q.CheckPrimality(StandardRSA.Compatibility.Default), null);

            // InverseQ
            // RFC 8017: q * qInv == 1 (mod p)
            Assert.AreEqual(BigInteger.One, q * inverseQ % p);

            // N
            if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.RequireSecondMostSignificantBit))
            {
                Assert.AreEqual(keyLength, n.GetBitLength());
            }
            Assert.AreEqual(p * q, n);

            // P - 1
            BigInteger pMinusOne = p - 1;

            // Q - 1
            BigInteger qMinusOne = q - 1;

            // phi(n)
            BigInteger phiN = pMinusOne * qMinusOne;

            // GCD(P - 1, Q - 1)
            BigInteger gcdN = BigInteger.GreatestCommonDivisor(pMinusOne, qMinusOne);

            // lambda(n)
            BigInteger lambdaN = phiN / gcdN;

            // E
            Assert.AreEqual(StandardRSA.ParameterE, e);
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(e, phiN));

            // D
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(d, lambdaN));
            Assert.IsTrue(d.CompareTo(BigInteger.One) >= 0);
            Assert.IsTrue(d.CompareTo(lambdaN) <= 0);
            // RFC 8017: e * d == 1 (mod \lambda(n))
            Assert.AreEqual(BigInteger.One, e * d % lambdaN);
            // The bit length of D should be close to the bit length of N - D should not be less than half the size of N
            double dBitLength = d.GetBitLength();
            double nBitLength = n.GetBitLength();
            double dnRatio = dBitLength / nBitLength;
            Assert.IsTrue(dnRatio > 0.5);
            Trace.WriteLine($"dBitLength({dBitLength}) / nBitLength({nBitLength}) = {dnRatio}");

            // DP
            // RFC 8017: e * dP == 1 (mod (p-1))
            Assert.AreEqual(BigInteger.One, e * dp % pMinusOne);

            // DQ
            // RFC 8017: e * dQ == 1 (mod (q-1))
            Assert.AreEqual(BigInteger.One, e * dq % qMinusOne);

            // Converting rsaParameters to RSA should work if the RSAParameters is properly formed
            // NB: Error 0xC100000D is thrown if the values of RSAParameters are bad, such as if they are not in big endian (network) byte order
            using RSA privateKey = RSA.Create(rsaParameters.Value);
            Assert.IsNotNull(privateKey);

            string privateKeyPem = CreatePem(rsaParameters.Value);
            Trace.WriteLine(privateKeyPem);
            return ByteEncoding.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(privateKeyPem)));
        }
    }
}

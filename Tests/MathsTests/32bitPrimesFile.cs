using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	public partial class PrimeTests
	{
		// The primes file is a binary file with all of the primes from 3 through 4,294,967,291 stored as little endian unsigned integers (i.e. each number has a 4-byte offset).
		// The function that creates the hashed prime groups expects this primes file "primes.32b" to be directly inside a zip file "primes32.zip".
		// The function that uses the primes file to get a specific prime number expects "primes.32b" to be uncompressed as it uses seeking (zip streaming doesn't support seek).
#if PRIMES_FILE
		private readonly object _primeBinaryFileLockObject = new();
		private const string filename = "primes.32b";
		private const string filenameCompressed = "primes32.zip";
		// TODO: Switch to 'Environment.SpecialFolder.Downloads' if it ever gets added to .NET
		private static readonly string downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
		private static readonly string filePathUncompressed = Path.Combine(downloadsDir, "primes32", filename);
		private static readonly string filePathCompressed = Path.Combine(downloadsDir, filenameCompressed);

		public uint GetPrime(int m10Offset, PrimeGroupSize groupSize, int groupIndex, int primeIndex)
		{
			using FileStream file = File.OpenRead(filePathUncompressed);
			Collection<int> sliceSizes = [5000, 10000, 10000, 25000, 50000, 50000, 50000, 100000, 100000, 100000, 250000, 250000, 500000, 500000, 500000, 500000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000];

			long offset = 10000000 * m10Offset;
			int groupOffset = 0;
			for (int i = 0; i < GetGroupOffsets(groupSize)[groupIndex]; i++)
			{
				groupOffset += sliceSizes[i];
			}
			offset += groupOffset;
			offset += primeIndex;
			offset *= 4;

			byte[] primeBytes = new byte[4];
			lock (_primeBinaryFileLockObject)
			{
				file.Seek(offset, SeekOrigin.Begin);
				file.ReadExactly(primeBytes);
			}
			uint prime = BitConverter.ToUInt32(primeBytes);
			return prime;
		}

		public static void CreatePrimeGroupHashes()
		{
			using ZipArchive archive = ZipFile.OpenRead(filePathCompressed);
			ZipArchiveEntry? file = archive.GetEntry(filename);
			Assert.IsNotNull(file);
			using Stream fileStream = file.Open();
			using SHA256 sha256FileBlock = SHA256.Create();
			using SHA256 sha256PrimeBlock = SHA256.Create();
			byte[] currentFilePrimeBytes = new byte[4];
			byte[] currentPrimeCandidateBytes = new byte[4];
			uint currentFilePrime = 1;
			//uint currentCandidate = 1;
			uint testedNumbers = 0;
			byte[] firstPrimeInBlock = new byte[4];
			int[] sliceSizes = [5000, 10000, 10000, 25000, 50000, 50000, 50000, 100000, 100000, 100000, 250000, 250000, 500000, 500000, 500000, 500000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000];
			int sliceSizeIndex = 0;
			int slicePrimeCount = 0;
			bool startOfSlice = true;
			while (testedNumbers < file.Length / 4)
			{
				fileStream.ReadExactly(currentFilePrimeBytes);
				sha256FileBlock.TransformBlock(currentFilePrimeBytes, 0, currentFilePrimeBytes.Length, null, 0);
				currentFilePrime = BitConverter.ToUInt32(currentFilePrimeBytes);
				if (startOfSlice)
				{
					Array.Copy(currentFilePrimeBytes, firstPrimeInBlock, firstPrimeInBlock.Length);
					startOfSlice = false;
				}
				//if (i != 0)
				//{
				//	currentCandidate = currentFilePrime - 2;
				//}
				//bool isPrime = false;
				//while (!isPrime)
				//{
				//	currentCandidate += 2;
				//	(isPrime, BigInteger? foundFactor) = BigIntegerExtensions.IsProbablePrime(currentCandidate, 10);
				//	testedNumbers++;
				//	if (isPrime)
				//	{
				//		currentPrimeCandidateBytes = BitConverter.GetBytes(currentCandidate);
				//		sha256PrimeBlock.TransformBlock(currentPrimeCandidateBytes, 0, currentPrimeCandidateBytes.Length, null, 0);
				//	}
				//}
				testedNumbers++;
				slicePrimeCount++;
				if (slicePrimeCount == sliceSizes[sliceSizeIndex] || testedNumbers == file.Length / 4)
				{
					//Trace.WriteLine($"Slice with index {sliceSizeIndex}, size of {sliceSizes[sliceSizeIndex]} complete after {slicePrimeCount} primes.");
					sha256FileBlock.TransformFinalBlock([], 0, 0);
					Trace.WriteLine($"{ByteEncoding.ToNetworkByteOrderHexString(firstPrimeInBlock)},{ByteEncoding.ToNetworkByteOrderHexString(currentFilePrimeBytes)},{ByteEncoding.ToHexString(sha256FileBlock.Hash)}");
					sha256FileBlock.Initialize();
					sliceSizeIndex++;
					if (sliceSizeIndex == sliceSizes.Length)
					{
						sliceSizeIndex = 0;
					}
					slicePrimeCount = 0;
					startOfSlice = true;
				}
			}
			Trace.WriteLine($"{nameof(currentFilePrime)}={currentFilePrime}, {sliceSizeIndex} slice index");
			//Trace.WriteLine($"{nameof(currentFilePrime)}={currentFilePrime}, {nameof(currentCandidate)}={currentCandidate}, {testedNumbers} odd numbers greater than 2 primality tested");
			//sha256FileBlock.TransformFinalBlock([], 0, 0);
			//Trace.WriteLine($"Prime file slice hashsum: {ByteEncoding.ToHexString(sha256FileBlock.Hash)}");
			//sha256PrimeBlock.TransformFinalBlock([], 0, 0);
			//Trace.WriteLine($"Found primes hashsum: {ByteEncoding.ToHexString(sha256PrimeBlock.Hash)}");
		}
#endif
	}
}

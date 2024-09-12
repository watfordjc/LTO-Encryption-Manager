using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	public partial class MathsTests
	{
		[TestMethod]
		public void PerfectSquareTest()
		{
			int testCount = 10;

			_ = Parallel.For(1, testCount + 1, testNumber => {
				Assert.IsFalse(testNumber == 0);

				// Base cases - negative numbers, 0, 1, and max values of signed and unsigned value types
				if (testNumber == 1)
				{
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(-2));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(-1));
					Assert.AreEqual((true, 0), BigIntegerExtensions.IsPerfectSquare(0));
					Assert.AreEqual((true, 1), BigIntegerExtensions.IsPerfectSquare(1));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(sbyte.MaxValue));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(byte.MaxValue));
					Assert.AreEqual((true, 16), BigIntegerExtensions.IsPerfectSquare((ushort)byte.MaxValue + 1));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(short.MaxValue));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(ushort.MaxValue));
					Assert.AreEqual((true, (ushort)byte.MaxValue + 1), BigIntegerExtensions.IsPerfectSquare((uint)ushort.MaxValue + 1));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(int.MaxValue));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(uint.MaxValue));
					Assert.AreEqual((true, (uint)ushort.MaxValue + 1), BigIntegerExtensions.IsPerfectSquare((ulong)uint.MaxValue + 1));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(long.MaxValue));
					Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(ulong.MaxValue));
					Assert.AreEqual((true, (ulong)uint.MaxValue + 1), BigIntegerExtensions.IsPerfectSquare(new BigInteger(ulong.MaxValue) + 1));
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}

				// Small numbers - 2^2 through 14^2
				else if (testNumber == 2)
				{
					for (int i = 2; i < 15; i++)
					{
						Assert.AreEqual((true, i), BigIntegerExtensions.IsPerfectSquare(i * i));
						//(bool perfectSquare, BigInteger? root) = BigIntegerExtensions.IsPerfectSquare(i);
						//Trace.WriteLine($"{i} {string.Format(CultureInfo.InvariantCulture, "{0}", perfectSquare ? "is" : "is not")} a perfect square{string.Format(CultureInfo.InvariantCulture, perfectSquare ? ": {0}^2" : string.Empty, root)}.");
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// byte^2
				else if (testNumber == 3)
				{
					long byteMaxLength = new BigInteger(byte.MaxValue).GetByteCount();
					// Random test - byteA * byteA
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[byteMaxLength];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// ushort^2
				else if (testNumber == 4)
				{
					long ushortMaxLength = new BigInteger(ushort.MaxValue).GetByteCount();
					// Random test - ushortA * ushortA
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[ushortMaxLength];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// uint^2
				else if (testNumber == 5)
				{
					long uintMaxLength = new BigInteger(uint.MaxValue).GetByteCount();
					// Random test - uintA * uintA
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[uintMaxLength];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// ulong^2
				else if (testNumber == 6)
				{
					long ulongMaxLength = new BigInteger(ulong.MaxValue).GetByteCount();
					// Random test - ulongA * ulongA
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[ulongMaxLength];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// Square of 512 bit BigInteger
				else if (testNumber == 7)
				{
					long maxLength512Bits = 512 / 8;
					// Random test - 512 bits * 512 bits
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[maxLength512Bits];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// Square of 1024 bit BigInteger
				else if (testNumber == 8)
				{
					long maxLength1024Bits = 1024 / 8;
					// Random test - 1024 bits * 1024 bits
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[maxLength1024Bits];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// Square of 2048 bit BigInteger
				else if (testNumber == 9)
				{
					long maxLength2048Bits = 2048 / 8;
					// Random test - 2048 bits * 2048 bits
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytes = new byte[maxLength2048Bits];
						RandomNumberGenerator.Fill(nBytes);
						BigInteger n = new(nBytes, true, true);
						Assert.AreEqual((true, n), BigIntegerExtensions.IsPerfectSquare(n * n));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
				// Two different 2048 bit BigInteger multiplied together
				else if (testNumber == 10)
				{
					long maxLength2048Bits = 2048 / 8;
					// Random test - 2048 bits * 2048 bits
					for (int i = 0; i < 10; i++)
					{
						Span<byte> nBytesA = new byte[maxLength2048Bits];
						Span<byte> nBytesB = new byte[maxLength2048Bits];
						RandomNumberGenerator.Fill(nBytesA);
						RandomNumberGenerator.Fill(nBytesB);
						while (nBytesB.SequenceEqual(nBytesA))
						{
							RandomNumberGenerator.Fill(nBytesB);
						}
						BigInteger bigIntegerA = new(nBytesA, true, true);
						BigInteger bigIntegerB = new(nBytesB, true, true);
						Assert.AreEqual((true, bigIntegerA), BigIntegerExtensions.IsPerfectSquare(bigIntegerA * bigIntegerA));
						Assert.AreEqual((true, bigIntegerB), BigIntegerExtensions.IsPerfectSquare(bigIntegerB * bigIntegerB));
						Assert.AreEqual((false, null), BigIntegerExtensions.IsPerfectSquare(bigIntegerA * bigIntegerB));
					}
					Trace.WriteLine($"Test {testNumber}/{testCount} completed successfully.");
				}
			});
		}
	}
}

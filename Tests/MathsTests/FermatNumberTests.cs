using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	public partial class MathsTests
	{
		[TestMethod]
		public void FermatNumberTest()
		{
			Assert.ThrowsException<ArgumentOutOfRangeException>(() => _ = BigIntegerExtensions.TryGetFermatNumberForBitLength(-1, out _));
			Assert.ThrowsException<ArgumentOutOfRangeException>(() => _ = BigIntegerExtensions.TryGetFermatNumberForBitLength(0, out _));
			Dictionary<int, BigInteger?> fermatNumberBitLengthDictionary = new()
			{
				{1, null},
				{2, 3 },
				{3, 5},
				{4, null},
				{5, 17},
				{6, null},
				{7, null},
				{8, null},
				{9, 257},
				{17, 65537},
				{32, null},
				{33, 4294967297},
				{64, null},
				{65, BigInteger.Parse("18446744073709551617", NumberStyles.None, CultureInfo.InvariantCulture)},
				{129, BigInteger.Parse("340282366920938463463374607431768211457", NumberStyles.None, CultureInfo.InvariantCulture)},
				{257, BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007913129639937", NumberStyles.None, CultureInfo.InvariantCulture)},
				{513, BigInteger.Parse("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084097", NumberStyles.None, CultureInfo.InvariantCulture)}
			};

			_ = Parallel.ForEach(fermatNumberBitLengthDictionary, dictionaryEntry =>
			{
				bool expectedResult = dictionaryEntry.Value != null;
				bool result = BigIntegerExtensions.TryGetFermatNumberForBitLength(dictionaryEntry.Key, out BigInteger? fermatNumber);
				Assert.AreEqual(expectedResult, result);
				Assert.AreEqual(dictionaryEntry.Value, fermatNumber);
				BigInteger testNumber = fermatNumber ?? BigInteger.Pow(2, dictionaryEntry.Key) - 1;
				bool result2 = testNumber.IsFermatNumber();
				Assert.AreEqual(expectedResult, result2);
				if (result)
				{
					Trace.WriteLine($"Bit length {dictionaryEntry.Key} result was {result}: {fermatNumber}");
				}
			});
		}
	}
}

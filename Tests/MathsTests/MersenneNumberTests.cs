using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	public partial class MathsTests
	{
		[TestMethod]
		public void MersenneNumberTest()
		{
			Dictionary<BigInteger, bool> numberIsMersenneDictionary = new()
			{
				{BigInteger.Pow(2, 1) - 1, true},
				{BigInteger.Pow(2, 2) - 1, true},
				{BigInteger.Pow(2, 3) - 1, true},
				{BigInteger.Pow(2, 4) - 1, true},
				{BigInteger.Pow(2, 5) - 1, true},
				{BigInteger.Pow(2, 6) - 1, true},
				{BigInteger.Pow(2, 7) - 1, true},
				{BigInteger.Pow(2, 8) - 1, true},
				{BigInteger.Pow(2, 16) - 1, true},
				{BigInteger.Pow(2, 32) - 1, true},
				{BigInteger.Pow(2, 64) - 1, true},
				{BigInteger.Pow(2, 128) - 1, true},
				{BigInteger.Pow(2, 256) - 1, true},
				{BigInteger.Pow(2, 512) - 1, true},
				{BigInteger.Pow(2, 1024) - 1, true},
				{BigInteger.Pow(2, 2048) - 1, true},
				{BigInteger.Pow(2, 4096) - 1, true},
				{BigInteger.Pow(2, 2) + 1, false},
				{BigInteger.Pow(2, 3) + 1, false},
				{BigInteger.Pow(2, 4) + 1, false},
				{BigInteger.Pow(2, 5) + 1, false},
				{BigInteger.Pow(2, 6) + 1, false},
				{BigInteger.Pow(2, 7) + 1, false},
				{BigInteger.Pow(2, 8) + 1, false},
				{BigInteger.Pow(2, 16) + 1, false},
				{BigInteger.Pow(2, 32) + 1, false},
				{BigInteger.Pow(2, 64) + 1, false},
				{BigInteger.Pow(2, 128) + 1, false},
				{BigInteger.Pow(2, 256) + 1, false},
				{BigInteger.Pow(2, 512) + 1, false},
				{BigInteger.Pow(2, 1024) + 1, false},
				{BigInteger.Pow(2, 2048) + 1, false},
				{BigInteger.Pow(2, 4096) + 1, false}
			};
			_ = Parallel.ForEach(numberIsMersenneDictionary, dictionaryEntry =>
			{
				bool expectedResult = dictionaryEntry.Value;
				bool result = BigIntegerExtensions.IsMersenneNumber(dictionaryEntry.Key);
				Trace.WriteLine($"{result} (expected {dictionaryEntry.Value}): {dictionaryEntry.Key}");
				Assert.AreEqual(expectedResult, result);
			});
		}
	}
}

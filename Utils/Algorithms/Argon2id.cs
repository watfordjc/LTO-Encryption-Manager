using CryptHash.Net.Hash.HashResults;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
    public static class Argon2id
    {
        public static Argon2idHashResult GetHash(CryptHash.Net.Hash.Argon2id argon2id, byte[] message, byte[] salt, int iterations, int memKibiBytes, int parallelism, int outputLength, byte[]? associatedData = null, byte[]? knownSecret = null)
        {
            ArgumentNullException.ThrowIfNull(argon2id);
            return argon2id.ComputeHash(
                    stringToComputeHashBytes: message,
                    iterations: iterations,
                    kBmemorySize: memKibiBytes,
                    degreeOfParallelism: parallelism,
                    amountBytesToReturn: outputLength,
                    salt: salt,
                    associatedData: associatedData,
                    knownSecret: knownSecret);
        }

        public static Argon2idHashResult GetKeyValidationHash(CryptHash.Net.Hash.Argon2id argon2id, byte[] password, byte[] salt, int outputLength)
        {
            return GetHash(
                argon2id: argon2id,
                message: password,
                salt: salt,
                iterations: 1,
                memKibiBytes: 2 << 20,
                parallelism: 4,
                outputLength: outputLength,
                associatedData: null,
                knownSecret: null);
        }
    }
}

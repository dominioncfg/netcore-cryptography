using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyTests.Core;

public record PasswordHashResult
{
    public byte[] Bytes { get; }
    public string String => Convert.ToBase64String(Bytes);
    public PasswordHashResult(byte[] bytes) => Bytes = bytes;
}

public static class PasswordHasher
{
    // * PasswordBasedKeyDerivationFunction is Known as PBKDF2.
    // * Part of the RSA Public Key Cryptographic Standards (PKCS #5 v2.0).
    // * Also part of the Internet  Engineering Task Force RFC2898.
    // * Goood Default for number of iteration is >= 100000.
    // * Is really slow but this is a good point in this case.

    public static PasswordHashResult ComputeHashPasswordUsingKeyDerivationFunction(string passwordToBeHashed, byte[] salt, int numberOfIterations)
    {
        //You can change the algorithm  used internally (By default is SH1)
        var algName = HashAlgorithmName.SHA1;
        //The number of output bytes that the chosen algorithm requires. 20 bytes in case SHA1.
        var sha1ResultLength = 20;

        using var hasher = new Rfc2898DeriveBytes(passwordToBeHashed, salt, numberOfIterations, algName);
        var hashedPassword = hasher.GetBytes(sha1ResultLength);
        return new PasswordHashResult(hashedPassword);
    }


    public static PasswordHashResult ClassicHashPasswordWithSalt(string passwordToBeHashed, byte[] salt)
    {
        using var sha256 = SHA256.Create();
        var passwordBytes = Encoding.UTF8.GetBytes(passwordToBeHashed);
        var hashedPassword = sha256.ComputeHash(Combine(passwordBytes, salt));
        return new PasswordHashResult(hashedPassword);
    }

    private static byte[] Combine(byte[] first, byte[] second)
    {
        var ret = new byte[first.Length + second.Length];

        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
        return ret;
    }
}

public static class Argon2idPasswordHasher
{
    public  static PasswordHashResult ComputeHashPassword(string passwordToBeHashed, byte[] salt, int numberOfIterations)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(passwordToBeHashed);
        var KnownSecret = CryptographicKey.CreateRandomOfBytes(16).Bytes;
        var unitMemorySize = 1048576;
        var keyLength = 16;

        var argon2 = new Argon2id(passwordBytes)
        {
            KnownSecret = KnownSecret,
            Salt = salt,
            DegreeOfParallelism = Environment.ProcessorCount,
            Iterations = numberOfIterations,
            MemorySize = Environment.ProcessorCount * unitMemorySize,
        };
        var hashed = argon2.GetBytes(keyLength);
        return new PasswordHashResult(hashed);
    }
}
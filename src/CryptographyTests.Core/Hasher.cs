using System.Security.Cryptography;
using System.Text;

namespace CryptographyTests.Core;

public record HashResult
{
    public byte[] Bytes { get; }
    public string String => Convert.ToBase64String(Bytes);
    public HashResult(byte[] bytes) => Bytes = bytes;
}

public static class Hasher
{
    public static HashResult ComputeMD5Hash(string toBeHashed)
    {
        //Not recommended after 2004
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = MD5.Create();
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeSha1(string toBeHashed)
    {
        //Not recommended after 2010
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = SHA1.Create();
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeSha2_256(string toBeHashed)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = SHA256.Create();
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeSha2_512(string toBeHashed)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = SHA512.Create();
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeSha3(string toBeHashed)
    {
        //Realy different from SHA2 but not part of .net base class library, needs a external library
        throw new NotImplementedException();
    }
}

public static class HmacHasher
{
    // * HMAC = Hash-based Message Authentication Code
    // * Used to simultaneously verify both the data integrity and authenticity of a message.
    // * Alternative to digital signatures with asymmetric cryptography
    // * Any cryptographic hash function, such as SHA-2 or SHA-3, may be used in the calculation of an HMAC; the resulting MAC algorithm is termed HMAC-X, where X is the hash function used (e.g. HMAC-SHA256 or HMAC-SHA3-512)
    // * The cryptographic strength of the HMAC depends upon the cryptographic strength of the underlying hash function, the size of its hash output, and the size and quality of the key. 

    public static HashResult ComputeHmacMD5Hash(string toBeHashed, byte[] key)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = new HMACMD5(key);
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeHmacSha1(string toBeHashed, byte[] key)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = new HMACSHA1(key);
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeHmacSha2_256(string toBeHashed, byte[] key)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = new HMACSHA256(key);
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }

    public static HashResult ComputeHmacSha2_512(string toBeHashed, byte[] key)
    {
        var bytes = Encoding.UTF8.GetBytes(toBeHashed);
        using var hasher = new HMACSHA512(key);
        var hash = hasher.ComputeHash(bytes);
        return new HashResult(hash);
    }
}
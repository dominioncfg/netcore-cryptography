using System.Security.Cryptography;

namespace CryptographyTests.Core;

public record CryptographicKey
{
    public byte[] Bytes { get; }
    public string String => Convert.ToBase64String(Bytes);
    public CryptographicKey(byte[] bytes) => Bytes = bytes;
 
    public static CryptographicKey CreateRandomOfBytes(int bytesCount)
    {
        return new CryptographicKey(RandomNumberGenerator.GetBytes(bytesCount));
    }
}
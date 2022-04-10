using System.Security.Cryptography;
using System.Text;

namespace CryptographyTests.Core;

public record DigitalSignatureKeyPairResult
{
    public byte[] PrivateKeyBytes { get; }
    public string PrivateKeyString => Convert.ToBase64String(PrivateKeyBytes);

    public byte[] PublicKeyBytes { get; }
    public string PublicKeyString => Convert.ToBase64String(PublicKeyBytes);

    public DigitalSignatureKeyPairResult(byte[] privateKey, byte[] publicKey)
    {
        PrivateKeyBytes = privateKey;
        PublicKeyBytes = publicKey;
    }
}

public record DigitalSignatureSignResult
{
    public byte[] SignatureBytes { get; }
    public string SignatureText => Convert.ToBase64String(HashBytes);

    public byte[] HashBytes { get; }
    public string HashText => Convert.ToBase64String(HashBytes);

    public DigitalSignatureSignResult(byte[] signature, byte[] hashedData)
    {
        SignatureBytes = signature;
        HashBytes = hashedData;
    }
}

public record DigitalVerifyResult
{
    public bool IsValid { get; }
    public DigitalVerifyResult(bool isValid) => IsValid = isValid;
}

public static class RsaDigitalSignature
{
    // * You need to sign hash of your message.

    public static DigitalSignatureKeyPairResult CreateKeyPair(int keyLengthInBytes)
    {
        using var rsa = RSA.Create(keyLengthInBytes);
        var privateKey = rsa.ExportRSAPrivateKey();
        var publicKey = rsa.ExportRSAPublicKey();
        return new DigitalSignatureKeyPairResult(privateKey, publicKey);
    }

    public static DigitalSignatureSignResult Sign(string signMessage, byte[] privateKey)
    {
        var hashedMessage = HashMessage(signMessage);

        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        var signature = rsa.SignHash(hashedMessage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new DigitalSignatureSignResult(signature, hashedMessage);
    }

    private static byte[] HashMessage(string data) => Hasher.ComputeSha2_256(data).Bytes;


    public static DigitalVerifyResult Verify(byte[] signature, byte[] publicKey, byte[] hashOfData)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        var result = rsa.VerifyHash(hashOfData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new DigitalVerifyResult(result);
    }
}


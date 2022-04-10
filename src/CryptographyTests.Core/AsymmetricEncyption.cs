using System.Security.Cryptography;
using System.Text;

namespace CryptographyTests.Core;

public record AsymmetricEncryptionKeyPairResult
{
    public byte[] PrivateKeyBytes { get; }
    public string PrivateKeyString => Convert.ToBase64String(PrivateKeyBytes);

    public byte[] PublicKeyBytes { get; }
    public string PublicKeyString => Convert.ToBase64String(PublicKeyBytes);

    public AsymmetricEncryptionKeyPairResult(byte[] privateKey, byte[] publicKey)
    {
        PrivateKeyBytes = privateKey;
        PublicKeyBytes = publicKey;
    }
}

public record ASymmetricEncryptionResult
{
    public byte[] ChipherTextBytes { get; }
    public string ChipherText => Convert.ToBase64String(ChipherTextBytes);
    public ASymmetricEncryptionResult(byte[] bytes) => ChipherTextBytes = bytes;
}

public record ASymmetricDecryptionResult
{
    public byte[] PlainTextInBytes => Encoding.UTF8.GetBytes(PlainText);
    public string PlainText { get; }
    public ASymmetricDecryptionResult(string str) => PlainText = str;
}

public static class RsaAsymmetricEncryption
{
    // * Tech developed by a company name RSA and based on prime numbers
    // * Can only encrypt data smaller than the key
    // * Common key sizes are 1024 (128 bytes), 2048 (256 bytes), 4096 (512 bytes) bits. Use At least 2048.
    // * The size of the key affects performance


    public static AsymmetricEncryptionKeyPairResult CreateKeyPair(int keyLengthInBytes)
    {
        using var rsa = RSA.Create(keyLengthInBytes);
        var privateKey = rsa.ExportRSAPrivateKey();
        var publicKey = rsa.ExportRSAPublicKey();
        return new AsymmetricEncryptionKeyPairResult(privateKey, publicKey);
    }

    public static ASymmetricEncryptionResult Encrypt(string plainText, byte[] publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        var plainTextInBytes = Encoding.UTF8.GetBytes(plainText);
        var chiperTextBytes = rsa.Encrypt(plainTextInBytes, RSAEncryptionPadding.OaepSHA256);
        return new ASymmetricEncryptionResult(chiperTextBytes);
    }

    public static ASymmetricDecryptionResult Decrypt(string chiperTextInBase64String, byte[] privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        var cipherTextBytes = Convert.FromBase64String(chiperTextInBase64String);
        var chiperTextBytes = rsa.Decrypt(cipherTextBytes, RSAEncryptionPadding.OaepSHA256);

        return new ASymmetricDecryptionResult(Encoding.UTF8.GetString(chiperTextBytes));
    }
}

public static class RsaWithEncryptedKeysAsymmetricEncryption
{
    // * This shows how to encrypt and decrypt private key in rsa
    // * Can only encrypt data smaller than the key
    // * Common key sizes are 1024 (128 bytes), 2048 (256 bytes), 4096 (512 bytes) bits. Use At least 2048.
    // * The size of the key affects performance


    public static AsymmetricEncryptionKeyPairResult CreateKeyPair(int keyLengthInBytes, string password)
    {
        using var rsa = RSA.Create(keyLengthInBytes);

        byte[] encryptedPrivateKey = new byte[keyLengthInBytes];
        var arraySpan = new Span<byte>(encryptedPrivateKey);
        var encParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000000);
        var success = rsa.TryExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encParams, arraySpan, out var writtenBytes);
        var encryptedMeaningfulBytes = encryptedPrivateKey.Take(writtenBytes).ToArray();
        var publicKey = rsa.ExportRSAPublicKey();
        return new AsymmetricEncryptionKeyPairResult(encryptedMeaningfulBytes, publicKey);
    }

    public static ASymmetricEncryptionResult Encrypt(string plainText, byte[] publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        var plainTextInBytes = Encoding.UTF8.GetBytes(plainText);
        var chiperTextBytes = rsa.Encrypt(plainTextInBytes, RSAEncryptionPadding.OaepSHA256);
        return new ASymmetricEncryptionResult(chiperTextBytes);
    }

    public static ASymmetricDecryptionResult DecryptWithEncryptedPrivateKey(string chiperTextInBase64String, byte[] encriptedPrivateKey, string password)
    {
        using var rsa = RSA.Create();
        rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encriptedPrivateKey, out _);

        var cipherTextBytes = Convert.FromBase64String(chiperTextInBase64String);
        var chiperTextBytes = rsa.Decrypt(cipherTextBytes, RSAEncryptionPadding.OaepSHA256);

        return new ASymmetricDecryptionResult(Encoding.UTF8.GetString(chiperTextBytes));
    }
}
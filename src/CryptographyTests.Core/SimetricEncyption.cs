using System.Security.Cryptography;
using System.Text;

namespace CryptographyTests.Core;

public record SymmetricEncryptionResult
{
    public byte[] Bytes { get; }
    public string String => Convert.ToBase64String(Bytes);
    public SymmetricEncryptionResult(byte[] bytes) => Bytes = bytes;
}

public record SymmetricDecryptionResult
{
    public byte[] Bytes => Encoding.UTF8.GetBytes(String);
    public string String { get; }
    public SymmetricDecryptionResult(string str) => String = str;
}

public static class DesSymmetricEncryption
{
    // * DES should not be used in modern software;
    // * Key is 8 bytes long (64 bits) ;
    const string AlgName = "DES";

    public static CryptographicKey GetRandomInitializationVector(int keyLength)
    {
        //DES uses 8 bytes IV but for some reason in .Net the key and IV needs to have the same length.
        return CryptographicKey.CreateRandomOfBytes(keyLength);
    }

    public static SymmetricEncryptionResult Encrypt(string plainText, byte[] key, byte[] initializationVector)
    {
        var toBeEncryptedBytes = Encoding.UTF8.GetBytes(plainText);
        using var des = DES.Create(AlgName);

        //Defaults 
        des!.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;

        des.Key = key;
        des.IV = initializationVector;

        using var memStream = new MemoryStream();

        var cryptoStream = new CryptoStream(memStream, des.CreateEncryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(toBeEncryptedBytes, 0, toBeEncryptedBytes.Length);
        cryptoStream.FlushFinalBlock();

        var encryptionResult = memStream.ToArray();
        return new SymmetricEncryptionResult(encryptionResult);
    }

    public static SymmetricDecryptionResult Decrypt(string cipherTextIn64Base, byte[] key, byte[] initializationVector)
    {
        var cipherTextBytes = Convert.FromBase64String(cipherTextIn64Base);
        using var des = DES.Create(AlgName);

        //Defaults 
        des!.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;

        des.Key = key;
        des.IV = initializationVector;

        using var memStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memStream, des.CreateDecryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(cipherTextBytes, 0, cipherTextBytes.Length);
        cryptoStream.FlushFinalBlock();

        var decryptionResult = memStream.ToArray();
        return new SymmetricDecryptionResult(Encoding.UTF8.GetString(decryptionResult));
    }
}

public static class TripleDesSymmetricEncryption
{
    // * Triple DES should not be used in modern software;
    // * Triple DES uses 2 or 3 keys of 8 (64 bits) bytes each; but you need to pass one Key with 16 bytes o 24 bytes and .Net will decouple them
    //

    public static CryptographicKey GetRandomInitializationVector()
    {
        //DES uses 8 bytes IV.
        return CryptographicKey.CreateRandomOfBytes(8);
    }

    public static SymmetricEncryptionResult Encrypt(string plainText, byte[] key, byte[] initializationVector)
    {
        if (key.Length != 16 && key.Length != 24)
            throw new ArgumentException("Invalid key. Triple DES requires 16 or 24 bytes keys.");

        var toBeEncryptedBytes = Encoding.UTF8.GetBytes(plainText);
        using var tripleDes = TripleDES.Create();

        //Defaults 
        tripleDes!.Mode = CipherMode.CBC;
        tripleDes.Padding = PaddingMode.PKCS7;

        tripleDes.Key = key;
        tripleDes.IV = initializationVector;

        using var memStream = new MemoryStream();

        var cryptoStream = new CryptoStream(memStream, tripleDes.CreateEncryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(toBeEncryptedBytes, 0, toBeEncryptedBytes.Length);
        cryptoStream.FlushFinalBlock();

        var encryptionResult = memStream.ToArray();
        return new SymmetricEncryptionResult(encryptionResult);
    }

    public static SymmetricDecryptionResult Decrypt(string cipherTextIn64Base, byte[] key, byte[] initializationVector)
    {
        var cipherTextBytes = Convert.FromBase64String(cipherTextIn64Base);
        using var tripleDes = TripleDES.Create();

        //Defaults 
        tripleDes!.Mode = CipherMode.CBC;
        tripleDes.Padding = PaddingMode.PKCS7;

        tripleDes.Key = key;
        tripleDes.IV = initializationVector;

        using var memStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memStream, tripleDes.CreateDecryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(cipherTextBytes, 0, cipherTextBytes.Length);
        cryptoStream.FlushFinalBlock();

        var decryptionResult = memStream.ToArray();
        return new SymmetricDecryptionResult(Encoding.UTF8.GetString(decryptionResult));
    }
}

public static class AesSymmetricEncryption
{
    // AES = Advanced Encryption Standard
    // * National Institute of Standards and Technology
    // * Was selected as part of a contest to replace DES
    // * Key can be 128, 192, 256 bits length.

    //Defer to OS libraries
    const string AlgName = nameof(AesCryptoServiceProvider);
    static readonly HashSet<int> allowedKeySizesInBytes = new()
    {
        16, //= 128 bits 
        24, //= 192 bits
        32, //= 256 bits 
    };
    const int InitializationVectorSizeInBytes = 16;

    public static CryptographicKey GetRandomInitializationVector()
    {
        //AES uses 16 bytes IV
        return CryptographicKey.CreateRandomOfBytes(InitializationVectorSizeInBytes);
    }

    public static SymmetricEncryptionResult Encrypt(string plainText, byte[] key, byte[] initializationVector)
    {
        if (!allowedKeySizesInBytes.Contains(key.Length))
            throw new ArgumentException("The key has an invalid size");

        if (initializationVector.Length != InitializationVectorSizeInBytes)
            throw new ArgumentException("The initializationVector has an invalid size");

        var toBeEncryptedBytes = Encoding.UTF8.GetBytes(plainText);
        using var aes = Aes.Create(AlgName);

        //Defaults 
        aes!.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.Key = key;
        aes.IV = initializationVector;

        using var memStream = new MemoryStream();

        var cryptoStream = new CryptoStream(memStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(toBeEncryptedBytes, 0, toBeEncryptedBytes.Length);
        cryptoStream.FlushFinalBlock();

        var encryptionResult = memStream.ToArray();
        return new SymmetricEncryptionResult(encryptionResult);
    }

    public static SymmetricDecryptionResult Decrypt(string cipherTextIn64Base, byte[] key, byte[] initializationVector)
    {
        if (!allowedKeySizesInBytes.Contains(key.Length))
            throw new ArgumentException("The key has an invalid size");

        if (initializationVector.Length != InitializationVectorSizeInBytes)
            throw new ArgumentException("The initializationVector has an invalid size");

        var cipherTextBytes = Convert.FromBase64String(cipherTextIn64Base);
        using var aes = Aes.Create(AlgName);

        //Defaults 
        aes!.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.Key = key;
        aes.IV = initializationVector;

        using var memStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

        cryptoStream.Write(cipherTextBytes, 0, cipherTextBytes.Length);
        cryptoStream.FlushFinalBlock();

        var decryptionResult = memStream.ToArray();
        return new SymmetricDecryptionResult(Encoding.UTF8.GetString(decryptionResult));
    }
}

//****AES GCM
public record AesGcmSymmetricEncryptionResult
{
    public byte[] CipherTextBytes { get; }
    public string CipherTextString => Convert.ToBase64String(CipherTextBytes);
    public byte[] TagBytes { get; }
    public string TagString => Convert.ToBase64String(TagBytes);
    public AesGcmSymmetricEncryptionResult(byte[] chipherText, byte[] tag)
    {
        CipherTextBytes = chipherText;
        TagBytes = tag;
    }
}

public record AesGcmSymmetricDecryptionResult
{
    public byte[] PlainTextBytes => Encoding.UTF8.GetBytes(PlainText);
    public string PlainText { get; }
    public AesGcmSymmetricDecryptionResult(string plainText) => PlainText = plainText;
}

public static class AesGcmSymmetricEncryption
{
    // * Consist of Aes + Galois Counter Mode
    // * Consist on Aes + MAC on the chiper text
    // * There is another AES CCM

    static readonly HashSet<int> allowedKeySizesInBytes = new()
    {
        16, //= 128 bits 
        24, //= 192 bits
        32, //= 256 bits 
    };
    const int NonceSizeInBytes = 12;
    const int TagSizeInBytes = 16;

    public static CryptographicKey GetRandomNonce()
    {
        //AES Gcm uses 12 bytes nonce (IV)
        return CryptographicKey.CreateRandomOfBytes(NonceSizeInBytes);
    }

    public static AesGcmSymmetricEncryptionResult Encrypt(string plainText, byte[] key, byte[] nonce, byte[]? associatedData = null)
    {
        if (!allowedKeySizesInBytes.Contains(key.Length))
            throw new ArgumentException("The key has an invalid size");

        if (nonce.Length != NonceSizeInBytes)
            throw new ArgumentException("The initializationVector has an invalid size");

        var toBeEncryptedBytes = Encoding.UTF8.GetBytes(plainText);
        using var aesGcm = new AesCcm(key);

        var tag = new byte[TagSizeInBytes];
        var chipherText = new byte[toBeEncryptedBytes.Length];

        aesGcm.Encrypt(nonce, toBeEncryptedBytes, chipherText, tag, associatedData);

        return new AesGcmSymmetricEncryptionResult(chipherText, tag);
    }

    public static AesGcmSymmetricDecryptionResult Decrypt(string cipherTextIn64Base, byte[] key, byte[] nonce, byte[] tag, byte[]? associatedData = null)
    {
        if (!allowedKeySizesInBytes.Contains(key.Length))
            throw new ArgumentException("The key has an invalid size");

        if (nonce.Length != NonceSizeInBytes)
            throw new ArgumentException("The initializationVector has an invalid size");

        if (tag.Length != TagSizeInBytes)
            throw new ArgumentException("The tag has an invalid size");

        var cipherTextBytes = Convert.FromBase64String(cipherTextIn64Base);
        var plainTextBytes = new byte[cipherTextBytes.Length];

        using var aesGcm = new AesCcm(key);
        aesGcm.Decrypt(nonce, cipherTextBytes, tag, plainTextBytes, associatedData);

        return new AesGcmSymmetricDecryptionResult(Encoding.UTF8.GetString(plainTextBytes));
    }
}
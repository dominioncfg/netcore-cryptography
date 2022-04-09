using CryptographyTests.Core;

namespace CryptographyTests.Host;

public static class Program
{
    static void Main()
    {
        //GenerateAndPrintRandomKey();

        //TestCoreHashingFunctions();
        //TestHmacHashingFunctions();
        //TestPasswordHashingTechnique();

        //TestDesSymmetricEncryption();
        //TestTripleDesSymmetricEncryption();
        //TestAesSymmetricEncryption();
        TestAesGcmSymmetricEncryption();

        Console.WriteLine("Press any key to close...");
        Console.ReadLine();

    }

    private static void GenerateAndPrintRandomKey()
    {
        var key = CryptographicKey.CreateRandomOfBytes(32);
        Console.WriteLine(key.String);
    }

    private static void TestCoreHashingFunctions()
    {
        var messageToBeHashed = "This is a really really really important message";

        var hashers = new Dictionary<string, Func<string, HashResult>>()
        {
            { "MD5", (str) => Hasher.ComputeMD5Hash(str)},
            { "SHA1", (str) => Hasher.ComputeSha1(str)},
            { "SHA2_256", (str) => Hasher.ComputeSha2_256(str)},
            { "SHA2_512", (str) => Hasher.ComputeSha2_512(str)},
        };

        foreach (var hasher in hashers)
        {
            var value = hasher.Value(messageToBeHashed);

            Console.WriteLine("***");
            Console.WriteLine($"Message: {messageToBeHashed}");
            Console.WriteLine($"HASH {hasher.Key}: {value.String} ({value.Bytes.Length} bytes length)");
            Console.WriteLine("***");
        }
    }

    private static void TestHmacHashingFunctions()
    {
        var keys = new[]
        {
            CryptographicKey.CreateRandomOfBytes(32),
            CryptographicKey.CreateRandomOfBytes(64),
        };
        var key64 = CryptographicKey.CreateRandomOfBytes(64);
        var messageToBeHashed = "This is a really really really important message";

        var hashers = new Dictionary<string, Func<string, byte[], HashResult>>()
        {
            { "HMac_MD5", (str, key) => HmacHasher.ComputeHmacMD5Hash(str,key)},
            { "HMac_SHA1", (str, key) => HmacHasher.ComputeHmacSha1(str,key)},
            { "HMac_SHA2_256", (str, key) => HmacHasher.ComputeHmacSha2_256(str,key)},
            { "HMac_SHA2_512", (str, key) => HmacHasher.ComputeHmacSha2_512(str,key)},
        };

        foreach (var hasher in hashers)
        {
            Console.WriteLine("***");
            foreach (var key in keys)
            {
                var value = hasher.Value(messageToBeHashed, key.Bytes);
                Console.WriteLine("**");
                Console.WriteLine($"Key: {key.String} ({key.Bytes.Length} bytes length)");
                Console.WriteLine($"Message: {messageToBeHashed}");
                Console.WriteLine($"HASH {hasher.Key}: {value.String} ({value.Bytes.Length} bytes length)");
                Console.WriteLine("**");
            }
            Console.WriteLine("***");
        }
    }

    private static void TestPasswordHashingTechnique()
    {
        //In real life this could be something like UserCreatedDate + some constant string or something that you stored in the db since is needed to check the password when login in
        //Another posibility is to store this random values in the db.
        //Is best having differnt values for each user instead of the same salt for everyone
        var salt = CryptographicKey.CreateRandomOfBytes(64).Bytes;
        var numberOfIterations = 100000;

        var passwordToBeHashed = "SuperPassword";

        Console.WriteLine("**");
        var pBKDF2Result = PasswordHasher.ComputeHashPasswordUsingKeyDerivationFunction(passwordToBeHashed, salt, numberOfIterations);
        Console.WriteLine($"Password Hashed with Native Key Derivation Function: {pBKDF2Result.String} ({pBKDF2Result.Bytes.Length} bytes length)");
        Console.WriteLine("**");


        Console.WriteLine("**");
        var classicHash = PasswordHasher.ClassicHashPasswordWithSalt(passwordToBeHashed, salt);
        Console.WriteLine($"Classic Password Hashed with Manually: {classicHash.String} ({classicHash.Bytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestDesSymmetricEncryption()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";
        var key = CryptographicKey.CreateRandomOfBytes(8);
        var iv = DesSymmetricEncryption.GetRandomInitializationVector(key.Bytes.Length);

        var encrypted = DesSymmetricEncryption.Encrypt(toBeEncrypted, key.Bytes, iv.Bytes);
        var decrypted = DesSymmetricEncryption.Decrypt(encrypted.String, key.Bytes, iv.Bytes);

        Console.WriteLine("**");
        Console.WriteLine("DES Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Key: {key.String}  ({key.Bytes.Length} bytes length)");
        Console.WriteLine($"IV: {iv.String}  ({iv.Bytes.Length} bytes length)");
        Console.WriteLine($"Encrypted: {encrypted.String}  ({encrypted.Bytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.String}  ({decrypted.Bytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestTripleDesSymmetricEncryption()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";
        //Remember this is actually 2 keys of 8 byte each
        var key = CryptographicKey.CreateRandomOfBytes(16);
        var iv = TripleDesSymmetricEncryption.GetRandomInitializationVector();

        var encrypted = TripleDesSymmetricEncryption.Encrypt(toBeEncrypted, key.Bytes, iv.Bytes);
        var decrypted = TripleDesSymmetricEncryption.Decrypt(encrypted.String, key.Bytes, iv.Bytes);

        Console.WriteLine("**");
        Console.WriteLine("DES Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Key: {key.String}  ({key.Bytes.Length} bytes length)");
        Console.WriteLine($"IV: {iv.String}  ({iv.Bytes.Length} bytes length)");
        Console.WriteLine($"Encrypted: {encrypted.String}  ({encrypted.Bytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.String}  ({decrypted.Bytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestAesSymmetricEncryption()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";

        var key = CryptographicKey.CreateRandomOfBytes(32);
        var iv = AesSymmetricEncryption.GetRandomInitializationVector();

        var encrypted = AesSymmetricEncryption.Encrypt(toBeEncrypted, key.Bytes, iv.Bytes);
        var decrypted = AesSymmetricEncryption.Decrypt(encrypted.String, key.Bytes, iv.Bytes);


        Console.WriteLine("**");
        Console.WriteLine("Aes CBC Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Key: {key.String}  ({key.Bytes.Length} bytes length)");
        Console.WriteLine($"IV: {iv.String}  ({iv.Bytes.Length} bytes length)");
        Console.WriteLine($"Encrypted: {encrypted.String}  ({encrypted.Bytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.String}  ({decrypted.Bytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestAesGcmSymmetricEncryption()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";

        var key = CryptographicKey.CreateRandomOfBytes(32);
        var nonce = AesGcmSymmetricEncryption.GetRandomNonce();
        //Can be anything of any length
        var associatedData = CryptographicKey.CreateRandomOfBytes(1000);

        var encrypted = AesGcmSymmetricEncryption.Encrypt(toBeEncrypted, key.Bytes, nonce.Bytes, associatedData.Bytes);
        var decrypted = AesGcmSymmetricEncryption.Decrypt(encrypted.CipherTextString, key.Bytes, nonce.Bytes, encrypted.TagBytes, associatedData.Bytes);

        Console.WriteLine("**");
        Console.WriteLine("Aes CBC Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Key: {key.String}  ({key.Bytes.Length} bytes length)");
        Console.WriteLine($"Nonce: {nonce.String}  ({nonce.Bytes.Length} bytes length)");
        Console.WriteLine($"Encrypted CipherText: {encrypted.CipherTextString}  ({encrypted.CipherTextBytes.Length} bytes length)");
        Console.WriteLine($"Encrypted Tag: {encrypted.TagString}  ({encrypted.TagBytes.Length} bytes length)");
        Console.WriteLine($"Associated Data: {associatedData.String}  ({associatedData.Bytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.PlainText}  ({decrypted.PlainText.Length} bytes length)");
        Console.WriteLine("**");
    }
}




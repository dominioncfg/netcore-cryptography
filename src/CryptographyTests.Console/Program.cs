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
        //TestAesGcmSymmetricEncryption();


        //TestRsaAsymmetricEncryption();
        //TestRsaAsymmetricEncryptionWithEncrpytedPrivateKey();

        //TestRsaDigitalSignature();

        //TestHybridEncryption();

        TestAll();

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

        Console.WriteLine("**");
        var argonPassHash = Argon2idPasswordHasher.ComputeHashPassword(passwordToBeHashed, salt, 2);
        Console.WriteLine($"Argon2id Password hashed: {argonPassHash.String} ({argonPassHash.Bytes.Length} bytes length)");
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
        Console.WriteLine("Aes GCM Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Key: {key.String}  ({key.Bytes.Length} bytes length)");
        Console.WriteLine($"Nonce: {nonce.String}  ({nonce.Bytes.Length} bytes length)");
        Console.WriteLine($"Encrypted CipherText: {encrypted.CipherTextString}  ({encrypted.CipherTextBytes.Length} bytes length)");
        Console.WriteLine($"Encrypted Tag: {encrypted.TagString}  ({encrypted.TagBytes.Length} bytes length)");
        Console.WriteLine($"Associated Data: {associatedData.String}  ({associatedData.Bytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.PlainText}  ({decrypted.PlainText.Length} bytes length)");
        Console.WriteLine("**");
    }


    private static void TestRsaAsymmetricEncryption()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";

        var keyPair = RsaAsymmetricEncryption.CreateKeyPair(2048);
        var encrypted = RsaAsymmetricEncryption.Encrypt(toBeEncrypted, keyPair.PublicKeyBytes);
        var decrypted = RsaAsymmetricEncryption.Decrypt(encrypted.ChipherText, keyPair.PrivateKeyBytes);

        Console.WriteLine("**");
        Console.WriteLine("RSA Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Public Key: {keyPair.PublicKeyString}  ({keyPair.PublicKeyBytes.Length} bytes length)");
        Console.WriteLine($"Private Key: {keyPair.PrivateKeyString}  ({keyPair.PrivateKeyBytes.Length} bytes length)");
        Console.WriteLine($"Encrypted CipherText: {encrypted.ChipherText}  ({encrypted.ChipherTextBytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.PlainText}  ({decrypted.PlainTextInBytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestRsaAsymmetricEncryptionWithEncrpytedPrivateKey()
    {
        var toBeEncrypted = "Here is some really large large and large text to play around";

        // A random password to encrypt the private key
        var password = CryptographicKey.CreateRandomOfBytes(32);

        var keyPair = RsaWithEncryptedKeysAsymmetricEncryption.CreateKeyPair(4096, password.String);
        var encrypted = RsaWithEncryptedKeysAsymmetricEncryption.Encrypt(toBeEncrypted, keyPair.PublicKeyBytes);
        var decrypted = RsaWithEncryptedKeysAsymmetricEncryption.DecryptWithEncryptedPrivateKey(encrypted.ChipherText, keyPair.PrivateKeyBytes, password.String);

        Console.WriteLine("**");
        Console.WriteLine("RSA Encryption");
        Console.WriteLine($"Text: {toBeEncrypted}");
        Console.WriteLine($"Public Key: {keyPair.PublicKeyString}  ({keyPair.PublicKeyBytes.Length} bytes length)");
        Console.WriteLine($"Private Key: {keyPair.PrivateKeyString}  ({keyPair.PrivateKeyBytes.Length} bytes length)");
        Console.WriteLine($"Encrypted CipherText: {encrypted.ChipherText}  ({encrypted.ChipherTextBytes.Length} bytes length)");
        Console.WriteLine($"Decrypted: {decrypted.PlainText}  ({decrypted.PlainTextInBytes.Length} bytes length)");
        Console.WriteLine("**");
    }

    private static void TestRsaDigitalSignature()
    {
        var toBeSigned = "Here is some really large large and large text to play around";

        var keyPair = RsaDigitalSignature.CreateKeyPair(4096);
        var signed = RsaDigitalSignature.Sign(toBeSigned, keyPair.PrivateKeyBytes);
        var verify = RsaDigitalSignature.Verify(signed.SignatureBytes, keyPair.PublicKeyBytes, signed.HashBytes);

        Console.WriteLine("**");
        Console.WriteLine("RSA DigitalSignature");
        Console.WriteLine($"Text: {toBeSigned}");
        Console.WriteLine($"Public Key: {keyPair.PublicKeyString}  ({keyPair.PublicKeyBytes.Length} bytes length)");
        Console.WriteLine($"Private Key: {keyPair.PrivateKeyString}  ({keyPair.PrivateKeyBytes.Length} bytes length)");
        Console.WriteLine($"Signature: {signed.SignatureText}  ({signed.SignatureBytes.Length} bytes length)");
        Console.WriteLine($"Signature Hash: {signed.HashText}  ({signed.HashBytes.Length} bytes length)");
        Console.WriteLine($"Verify: {verify.IsValid}");
        Console.WriteLine("**");
    }


    static void TestHybridEncryption()
    {
        var clientAddress = "Client";
        var serverAddress = "ServerAddress";

        var network = new ComputersNetworkSimulator();

        var client = new ClientComputer(clientAddress);
        var server = new ServerComputer(serverAddress);

        network.Register(client);
        network.Register(new TrustedComputer("TC1"));
        network.Register(server);

        var response = client.SendEncryptedRequestToServer(serverAddress, new SumRequestPayload()
        {
            A = 2,
            B = 3,
        });
        Console.WriteLine($"The server response {response}");
    }

    static void TestAll()
    {
        GenerateAndPrintRandomKey();

        TestCoreHashingFunctions();
        TestHmacHashingFunctions();
        TestPasswordHashingTechnique();

        TestDesSymmetricEncryption();
        TestTripleDesSymmetricEncryption();
        TestAesSymmetricEncryption();
        TestAesGcmSymmetricEncryption();


        TestRsaAsymmetricEncryption();
        TestRsaAsymmetricEncryptionWithEncrpytedPrivateKey();

        TestRsaDigitalSignature();

        TestHybridEncryption();
        Console.WriteLine("Press any key to close...");
        Console.ReadLine();
    }
}




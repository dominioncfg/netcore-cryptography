using System.Text;
using System.Text.Json;

namespace CryptographyTests.Core
{
    public interface IComputer
    {
        void ConfigureNetwork(IComputersNetwork network);

        EncryptedRequestResponseNetworkMessageResponse? HandleEncryptedRequestMessage(EncryptedRequestResponseNetworkMessage message);
        EncryptedRequestResponseNetworkMessageResponse HandleEncryptedResponseMessage(EncryptedRequestResponseNetworkMessageResponse responseMessage);
        PlainTextResponse? HandlePlainTextRequestMessage(PlainTextRequest message);
        PlainTextResponse HandlePlainTextResponseMessage(PlainTextResponse response);
    }

    public class EncryptedRequestResponseNetworkMessage
    {
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;
        public EncryptedPacket EncryptedPacket { get; set; } = new EncryptedPacket();
    }

    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey = Array.Empty<byte>();
        public byte[] EncryptedData = Array.Empty<byte>();
        public byte[] Nonce = Array.Empty<byte>();
        public byte[] Tag = Array.Empty<byte>();
    }

    public class EncryptedRequestResponseNetworkMessageResponse
    {
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;
        public EncryptedResponsePacket EncryptedPacket { get; set; } = new EncryptedResponsePacket();
    }

    public class EncryptedResponsePacket
    {
        public byte[] EncryptedData = Array.Empty<byte>();
        public byte[] Tag = Array.Empty<byte>();
    }

    public class PlainTextRequest
    {
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;

        public object? Payload { get; set; }
    }

    public class PlainTextResponse
    {
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;

        public object? Payload { get; set; }
    }

    public class EncryptedHandShakeRequest
    {

    }

    public class EncryptedHandShakeResponse
    {
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    }

    public class SumRequestPayload
    {
        public int A { get; set; }
        public int B { get; set; }
    }

    public class SumResponsePayload
    {
        public int Result { get; set; }
    }


    public interface IComputersNetwork
    {
        void Register(IComputer c);
        EncryptedRequestResponseNetworkMessageResponse RouteEncryptedMessage(IComputer sender, EncryptedRequestResponseNetworkMessage request);
        PlainTextResponse RoutePlainTextMessage(IComputer sender, PlainTextRequest request);
    }


    public class ComputersNetworkSimulator : IComputersNetwork
    {
        private readonly List<IComputer> _networkComputers = new();

        public void Register(IComputer c)
        {
            c.ConfigureNetwork(this);
            _networkComputers.Add(c);
        }

        public EncryptedRequestResponseNetworkMessageResponse RouteEncryptedMessage(IComputer sender, EncryptedRequestResponseNetworkMessage request)
        {
            MakeSureNetworkIsNotEmpty();
            var computerIndex = GetComputerLocationInNetwork(sender);
            MakeSureComputerExist(computerIndex);

            var affectedSubnet = GetMessageAffectedSubnet(computerIndex);
            MakeSureThereIsAtLeastAnotherPotentialReceiver(affectedSubnet);

            return PassEncryptedMessageAccrossTheNetwork(affectedSubnet, request);
        }
        public PlainTextResponse RoutePlainTextMessage(IComputer sender, PlainTextRequest request)
        {
            MakeSureNetworkIsNotEmpty();
            var computerIndex = GetComputerLocationInNetwork(sender);
            MakeSureComputerExist(computerIndex);

            var affectedSubnet = GetMessageAffectedSubnet(computerIndex);
            MakeSureThereIsAtLeastAnotherPotentialReceiver(affectedSubnet);


            return PassPlainTextMessageAccrossTheNetwork(affectedSubnet, request);
        }

        private void MakeSureNetworkIsNotEmpty()
        {
            if (_networkComputers.Count == 0)
                throw new Exception("Network is empty");
        }

        private int GetComputerLocationInNetwork(IComputer sender)
        {
            var index = _networkComputers.IndexOf(sender);
            return index;
        }

        private static void MakeSureComputerExist(int messageOriginComputerIndex)
        {
            if (messageOriginComputerIndex == -1)
                throw new Exception("Who dafuq are u");
        }

        private List<IComputer> GetMessageAffectedSubnet(int messageOriginComputerIndex)
        {
            return _networkComputers.Skip(messageOriginComputerIndex).ToList();
        }

        private static void MakeSureThereIsAtLeastAnotherPotentialReceiver(List<IComputer> computers)
        {
            if (computers.Count <= 1)
                throw new Exception("You are alone mate...");
        }

        private static EncryptedRequestResponseNetworkMessageResponse PassEncryptedMessageAccrossTheNetwork(List<IComputer> computers, EncryptedRequestResponseNetworkMessage request)
        {
            var passResponseTo = new List<IComputer>(computers.Count);
            EncryptedRequestResponseNetworkMessageResponse? response = null;

            passResponseTo.Add(computers.First());


            for (int i = 1; i < computers.Count; i++)
            {
                response = computers[i].HandleEncryptedRequestMessage(request);

                if (response is not null)
                    break;

                passResponseTo.Insert(0, computers[i]);
            }

            if (response is null)
                throw new Exception("No one could handle the request");

            foreach (var computer in passResponseTo)
            {
                computer.HandleEncryptedResponseMessage(response);
            }

            return response;
        }

        private static PlainTextResponse PassPlainTextMessageAccrossTheNetwork(List<IComputer> computers, PlainTextRequest request)
        {
            var passResponseTo = new List<IComputer>(computers.Count);
            PlainTextResponse? response = null;

            passResponseTo.Add(computers.First());


            for (int i = 1; i < computers.Count; i++)
            {
                response = computers[i].HandlePlainTextRequestMessage(request);

                if (response is not null)
                    break;

                passResponseTo.Insert(0, computers[i]);
            }

            if (response is null)
                throw new Exception("No one could handle the request");

            foreach (var computer in passResponseTo)
            {
                computer.HandlePlainTextResponseMessage(response);
            }

            return response;
        }
    }

    public abstract class ComputerBaseComputer : IComputer
    {
        public string Address { get; }

        private IComputersNetwork? network;
        protected IComputersNetwork? Network => network;

        public ComputerBaseComputer(string address)
        {
            Address = address;
        }

        public void ConfigureNetwork(IComputersNetwork network)
        {
            this.network = network;
        }

        public virtual EncryptedRequestResponseNetworkMessageResponse? HandleEncryptedRequestMessage(EncryptedRequestResponseNetworkMessage message)
        {
            return null;
        }

        public virtual EncryptedRequestResponseNetworkMessageResponse HandleEncryptedResponseMessage(EncryptedRequestResponseNetworkMessageResponse responseMessage)
        {
            return responseMessage;
        }

        public virtual PlainTextResponse? HandlePlainTextRequestMessage(PlainTextRequest message)
        {
            return null;
        }

        public virtual PlainTextResponse HandlePlainTextResponseMessage(PlainTextResponse response)
        {
            return response;
        }
    }

    public class ClientComputer : ComputerBaseComputer
    {
        private readonly Dictionary<string, byte[]> serverPublicKeys = new();
        private readonly Dictionary<string, (byte[] SessionKey, byte[] Nonce)> aesGcmSessionsKeysAndNonces = new();

        public ClientComputer(string address) : base(address) { }


        public object SendEncryptedRequestToServer(string serverAddress, object messagePayload)
        {
            DoHandShakeIfNeeded(serverAddress);
            return SendClientEncryptedRequest(serverAddress, messagePayload);
        }


        /// <summary>
        /// Gets the Public Key of the Server by sending a Request.
        /// </summary>
        /// <param name="serverAddress"></param>
        /// <exception cref="Exception"></exception>
        private void DoHandShakeIfNeeded(string serverAddress)
        {
            MakeSureWeHaveNetwork();

            bool publicKeyIsKnown = serverPublicKeys.ContainsKey(serverAddress);
            if (publicKeyIsKnown)
                return;

            var handShakeRequest = new PlainTextRequest()
            {
                From = this.Address,
                To = serverAddress,
                Payload = new EncryptedHandShakeRequest(),
            };

            var response = Network!.RoutePlainTextMessage(this, handShakeRequest);

            if (IsServerRespondingToMe(serverAddress, response))
            {
                if (response.Payload is EncryptedHandShakeResponse handShakeResponse)
                {
                    if (handShakeResponse.PublicKey is null || handShakeResponse.PublicKey.Length == 0)
                    {
                        throw new Exception("Fail to fetch server public key");
                    }
                    serverPublicKeys.Add(serverAddress, handShakeResponse.PublicKey);
                }
            }
        }

        public object SendClientEncryptedRequest(string serverAddress, object messagePayload)
        {
            MakeSureWeHaveNetwork();

            string message = JsonSerializer.Serialize(messagePayload);

            //Generate AES Keys
            var (sessionKey, nonce) = GetOrGenerateAesSessionKeyAndNonceForServer(serverAddress);

            //AES
            var aesGcmEncryptionResult = AesGcmSymmetricEncryption.Encrypt(message, sessionKey, nonce);

            //Encrypt with RSA the AES Key
            var serverRsaPublicKey = serverPublicKeys[serverAddress];
            var keyString = Convert.ToBase64String(sessionKey);
            var rsaKeyEncrypted = RsaAsymmetricEncryption.Encrypt(keyString, serverRsaPublicKey);

            var encryptedPacket = new EncryptedPacket
            {
                Nonce = nonce,
                EncryptedData = aesGcmEncryptionResult.CipherTextBytes,
                Tag = aesGcmEncryptionResult.TagBytes,
                EncryptedSessionKey = rsaKeyEncrypted.ChipherTextBytes,

            };

            var encrpytedRequest = new EncryptedRequestResponseNetworkMessage()
            {
                From = this.Address,
                To = serverAddress,
                EncryptedPacket = encryptedPacket,
            };

            var response = Network!.RouteEncryptedMessage(this, encrpytedRequest);

            if (IsServerRespondingToMe(serverAddress, response))
            {
                return DecryptIncomingServerResponseMessage(response);
            }

            throw new Exception("Unexpected Response");

        }

        private object DecryptIncomingServerResponseMessage(EncryptedRequestResponseNetworkMessageResponse encryptedMessage)
        {
            var aesSession = aesGcmSessionsKeysAndNonces[encryptedMessage.From];
            string messageEncText = Convert.ToBase64String(encryptedMessage.EncryptedPacket.EncryptedData);
            var messagePayloadDecrypted = AesGcmSymmetricEncryption.Decrypt(messageEncText, aesSession.SessionKey, aesSession.Nonce, encryptedMessage.EncryptedPacket.Tag);
            return JsonSerializer.Deserialize<object>(messagePayloadDecrypted.PlainText)?? throw new Exception("Fail to Deserialize");

        }

        private (byte[] SessionKey, byte[] Nonce) GetOrGenerateAesSessionKeyAndNonceForServer(string serverAddress)
        {
            if (aesGcmSessionsKeysAndNonces.ContainsKey(serverAddress))
                return aesGcmSessionsKeysAndNonces[serverAddress];

            //Aes with with 512 bits key
            var newSessionKey = CryptographicKey.CreateRandomOfBytes(32).Bytes;
            //12 bytes Nonce (IV)
            var newNonce = CryptographicKey.CreateRandomOfBytes(12).Bytes;

            aesGcmSessionsKeysAndNonces.Add(serverAddress, (newSessionKey, newNonce));

            return GetOrGenerateAesSessionKeyAndNonceForServer(serverAddress);
        }

        private void MakeSureWeHaveNetwork()
        {
            if (Network is null)
                throw new Exception("No Network");
        }

        private bool IsServerRespondingToMe(string serverAddress, EncryptedRequestResponseNetworkMessageResponse response)
        {
            return response.To == this.Address && response.From == serverAddress;
        }

        private bool IsServerRespondingToMe(string serverAddress, PlainTextResponse response)
        {
            return response.To == this.Address && response.From == serverAddress;
        }
    }

    public class ServerComputer : ComputerBaseComputer
    {
        AsymmetricEncryptionKeyPairResult AsymmetricEncryptionKeys { get; }

        public ServerComputer(string address) : base(address)
        {
            AsymmetricEncryptionKeys = RsaAsymmetricEncryption.CreateKeyPair(2048);
        }

        public override PlainTextResponse? HandlePlainTextRequestMessage(PlainTextRequest message)
        {
            if (!IsRequestForMe(message.To))
                return null;

            if (message.Payload is null)
                throw new Exception("No Message");

            switch (message.Payload)
            {
                case EncryptedHandShakeRequest _:
                    return HandleHandShakeRequest(message);
            }

            return null;
        }

        private PlainTextResponse HandleHandShakeRequest(PlainTextRequest message)
        {
            return new PlainTextResponse()
            {
                From = this.Address,
                To = message.From,
                Payload = new EncryptedHandShakeResponse()
                {
                    PublicKey = AsymmetricEncryptionKeys.PublicKeyBytes,
                },
            };
        }

        private bool IsRequestForMe(string requestTo) => Address == requestTo;


        public override EncryptedRequestResponseNetworkMessageResponse? HandleEncryptedRequestMessage(EncryptedRequestResponseNetworkMessage message)
        {
            if (!IsRequestForMe(message.To))
                return null;

            try
            {
                var (decryptedMessage, responseKey, nonce) = DecryptIncomingMessage(message);
                var responsePayload = HandleDecryptedMessage(decryptedMessage);
                var responseMessage = EncryptOutgoinResponse(message.From, responseKey, nonce, responsePayload);
                return responseMessage;
            }
            catch (Exception e)
            {
                throw new Exception("Message is corrupted", e);
            }
        }

        private EncryptedRequestResponseNetworkMessageResponse EncryptOutgoinResponse(string clientAddress, byte[] sessionKey, byte[] nonce, object responsePayload)
        {
            string message = JsonSerializer.Serialize(responsePayload);
            //AES
            var aesGcmEncryptionResult = AesGcmSymmetricEncryption.Encrypt(message, sessionKey, nonce);

            return new EncryptedRequestResponseNetworkMessageResponse()
            {
                To = clientAddress,
                From = Address,
                EncryptedPacket = new EncryptedResponsePacket()
                {
                    EncryptedData = aesGcmEncryptionResult.CipherTextBytes,
                    Tag = aesGcmEncryptionResult.TagBytes,
                }
            };
        }

        public static object HandleDecryptedMessage(string decryptedMessage)
        {
            try
            {
                var request = JsonSerializer.Deserialize<SumRequestPayload>(decryptedMessage);
                if (request is null)
                    throw new Exception("Fail to parse");

                return new SumResponsePayload() { Result = request.A + request.B };
            }
            catch (Exception e)
            {
                throw new Exception("BadRequest", e);
            }
        }

        public (string PayloadPlainText, byte[] AesEncryptionKey, byte[] Nonce) DecryptIncomingMessage(EncryptedRequestResponseNetworkMessage encryptedMessage)
        {
            var aesKeyString = Convert.ToBase64String(encryptedMessage.EncryptedPacket.EncryptedSessionKey);
            var decryptedSessionKey = RsaAsymmetricEncryption.Decrypt(aesKeyString, AsymmetricEncryptionKeys.PrivateKeyBytes);
            var decryptedSessionKeyIn64 = Convert.FromBase64String(decryptedSessionKey.PlainText);

            var strEncrypted = Convert.ToBase64String(encryptedMessage.EncryptedPacket.EncryptedData);

            var aesGcmDecryptedMessage = AesGcmSymmetricEncryption.Decrypt(strEncrypted, decryptedSessionKeyIn64, encryptedMessage.EncryptedPacket.Nonce, encryptedMessage.EncryptedPacket.Tag);
            return (aesGcmDecryptedMessage.PlainText, decryptedSessionKeyIn64, encryptedMessage.EncryptedPacket.Nonce);
        }
    }

    public class TrustedComputer : ComputerBaseComputer
    {
        public TrustedComputer(string address) : base(address)
        {

        }
        public override EncryptedRequestResponseNetworkMessageResponse? HandleEncryptedRequestMessage(EncryptedRequestResponseNetworkMessage message)
        {
            return null;
        }

        public override EncryptedRequestResponseNetworkMessageResponse HandleEncryptedResponseMessage(EncryptedRequestResponseNetworkMessageResponse responseMessage)
        {
            return responseMessage;
        }
    }
}

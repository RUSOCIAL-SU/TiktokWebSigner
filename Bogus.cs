using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace TikTokWeb
{
    public static class Bogus
    {
        private const string StandardB64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private const string CustomB64Alphabet = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe";

        private static readonly Dictionary<char, char> Base64CharMap;

        static Bogus()
        {
            Base64CharMap = new Dictionary<char, char>();
            for (int i = 0; i < StandardB64Alphabet.Length; i++)
            {
                Base64CharMap[StandardB64Alphabet[i]] = CustomB64Alphabet[i];
            }
        }

        private static string CustomB64Encode(byte[] inputBuffer)
        {
            string standardBase64 = Convert.ToBase64String(inputBuffer);
            var result = new StringBuilder();
            foreach (char character in standardBase64)
            {
                result.Append(Base64CharMap.TryGetValue(character, out char mappedChar) ? mappedChar : character);
            }
            return result.ToString();
        }

        private static byte[] ComputeMd5Hash(byte[] data)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }

        private static byte[] Rc4Encrypt(byte[] key, byte[] plaintext)
        {
            int[] sBox = new int[256];
            for (int i = 0; i < 256; i++)
                sBox[i] = i;

            int swapIndex = 0;
            int keyLength = key.Length;
            for (int i = 0; i < 256; i++)
            {
                swapIndex = (swapIndex + sBox[i] + key[i % keyLength]) & 0xFF;
                (sBox[i], sBox[swapIndex]) = (sBox[swapIndex], sBox[i]);
            }

            byte[] output = new byte[plaintext.Length];
            int stateIndexI = 0;
            int stateIndexJ = 0;
            for (int n = 0; n < plaintext.Length; n++)
            {
                stateIndexI = (stateIndexI + 1) & 0xFF;
                stateIndexJ = (stateIndexJ + sBox[stateIndexI]) & 0xFF;
                (sBox[stateIndexI], sBox[stateIndexJ]) = (sBox[stateIndexJ], sBox[stateIndexI]);
                int keyStreamByte = sBox[(sBox[stateIndexI] + sBox[stateIndexJ]) & 0xFF];
                output[n] = (byte)(plaintext[n] ^ keyStreamByte);
            }
            return output;
        }

        private static byte ComputeXorChecksum(byte[] buffer)
        {
            int accumulator = 0;
            foreach (byte byteValue in buffer)
            {
                accumulator ^= byteValue;
            }
            return (byte)(accumulator & 0xFF);
        }

        public static string Encrypt(string queryParams, string postData, string userAgent, long timestamp)
        {
            byte[] userAgentKey = new byte[] { 0x00, 0x01, 0x0E };
            byte[] encryptionKey = new byte[] { 0xFF };
            uint magicConstant = 0x4A41279F;

            byte[] queryParamsHash = ComputeMd5Hash(ComputeMd5Hash(Encoding.UTF8.GetBytes(queryParams)));
            byte[] postDataHash = ComputeMd5Hash(ComputeMd5Hash(Encoding.UTF8.GetBytes(postData)));

            byte[] encryptedUserAgent = Rc4Encrypt(userAgentKey, Encoding.UTF8.GetBytes(userAgent));
            string userAgentBase64 = Convert.ToBase64String(encryptedUserAgent);
            byte[] userAgentHash = ComputeMd5Hash(Encoding.ASCII.GetBytes(userAgentBase64));

            var payloadParts = new List<byte>();
            payloadParts.Add(0x40);
            payloadParts.AddRange(userAgentKey);
            payloadParts.Add(queryParamsHash[14]);
            payloadParts.Add(queryParamsHash[15]);
            payloadParts.Add(postDataHash[14]);
            payloadParts.Add(postDataHash[15]);
            payloadParts.Add(userAgentHash[14]);
            payloadParts.Add(userAgentHash[15]);

            uint timestampValue = (uint)(timestamp & 0xFFFFFFFF);
            payloadParts.Add((byte)((timestampValue >> 24) & 0xFF));
            payloadParts.Add((byte)((timestampValue >> 16) & 0xFF));
            payloadParts.Add((byte)((timestampValue >> 8) & 0xFF));
            payloadParts.Add((byte)(timestampValue & 0xFF));

            payloadParts.Add((byte)((magicConstant >> 24) & 0xFF));
            payloadParts.Add((byte)((magicConstant >> 16) & 0xFF));
            payloadParts.Add((byte)((magicConstant >> 8) & 0xFF));
            payloadParts.Add((byte)(magicConstant & 0xFF));

            byte[] payload = payloadParts.ToArray();
            byte checksum = ComputeXorChecksum(payload);

            byte[] payloadWithChecksum = new byte[payload.Length + 1];
            Array.Copy(payload, payloadWithChecksum, payload.Length);
            payloadWithChecksum[payload.Length] = checksum;

            byte[] encryptedPayload = Rc4Encrypt(encryptionKey, payloadWithChecksum);

            byte[] finalOutput = new byte[2 + encryptedPayload.Length];
            finalOutput[0] = 0x02;
            finalOutput[1] = encryptionKey[0];
            Array.Copy(encryptedPayload, 0, finalOutput, 2, encryptedPayload.Length);

            return CustomB64Encode(finalOutput);
        }

        public static string Sign(string queryString, string body, string userAgent, long timestamp)
        {
            return Encrypt(queryString, body, userAgent, timestamp);
        }
    }
}

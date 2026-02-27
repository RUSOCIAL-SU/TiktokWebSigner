using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace TikTokWeb
{
    /// <summary>
    /// Generates the X-Bogus signature token for TikTok web API requests.
    /// Constructs a payload from double-MD5 hashes of query, body, and user agent,
    /// then RC4-encrypts and encodes it with a custom base64 alphabet.
    /// </summary>
    public static class Bogus
    {
        private const string CustomBase64Alphabet = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=";
        private const string StandardBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        /// <summary>
        /// Computes the MD5 hash of raw bytes and returns it as a lowercase hex string.
        /// </summary>
        private static string ComputeMd5Hex(byte[] data)
        {
            return Convert.ToHexStringLower(MD5.HashData(data));
        }

        /// <summary>
        /// Computes the MD5 hash of a UTF-8 string and returns it as a lowercase hex string.
        /// </summary>
        private static string ComputeMd5Hex(string input)
        {
            return Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(input)));
        }

        /// <summary>
        /// Converts a lowercase hex string (e.g. "d41d8c") into its raw byte representation.
        /// Each pair of hex characters becomes one byte.
        /// </summary>
        private static byte[] HexStringToBytes(string hexString)
        {
            int byteCount = hexString.Length >> 1;
            byte[] result = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                result[i] = (byte)((HexCharToValue(hexString[2 * i]) << 4) | HexCharToValue(hexString[2 * i + 1]));
            }
            return result;
        }

        /// <summary>
        /// Returns the numeric value (0-15) of a single lowercase hex character.
        /// </summary>
        private static int HexCharToValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            return 0;
        }

        /// <summary>
        /// Performs RC4 stream cipher encryption/decryption on the data using the given key.
        /// Initializes a 256-byte S-box via key-scheduling, then XORs each data byte
        /// with the generated keystream.
        /// </summary>
        private static byte[] Rc4Encrypt(byte[] key, byte[] data)
        {
            int[] sBox = new int[256];
            for (int i = 0; i < 256; i++)
                sBox[i] = i;

            int swapIndex = 0;
            for (int i = 0; i < 256; i++)
            {
                swapIndex = (swapIndex + sBox[i] + key[i % key.Length]) % 256;
                int temp = sBox[i];
                sBox[i] = sBox[swapIndex];
                sBox[swapIndex] = temp;
            }

            int indexI = 0;
            int indexJ = 0;
            byte[] output = new byte[data.Length];
            for (int n = 0; n < data.Length; n++)
            {
                indexI = (indexI + 1) % 256;
                indexJ = (indexJ + sBox[indexI]) % 256;
                int temp = sBox[indexI];
                sBox[indexI] = sBox[indexJ];
                sBox[indexJ] = temp;
                output[n] = (byte)(255 & (data[n] ^ sBox[(sBox[indexI] + sBox[indexJ]) % 256]));
            }
            return output;
        }

        /// <summary>
        /// Encodes a byte array using a custom base64-like scheme (no padding).
        /// Processes the input in groups of 3 bytes, producing 4 characters each
        /// by indexing into the provided alphabet table.
        /// </summary>
        private static string CustomBase64Encode(byte[] input, string alphabet)
        {
            int groupCount = input.Length / 3;
            var encoded = new StringBuilder(groupCount * 4);
            for (int i = 0; i < groupCount; i++)
            {
                int byte1 = input[3 * i] & 255;
                int byte2 = input[3 * i + 1] & 255;
                int byte3 = input[3 * i + 2] & 255;
                int combined = (byte1 << 16) | (byte2 << 8) | byte3;
                encoded.Append(alphabet[(combined & 16515072) >> 18]);
                encoded.Append(alphabet[(combined & 258048) >> 12]);
                encoded.Append(alphabet[(combined & 4032) >> 6]);
                encoded.Append(alphabet[combined & 63]);
            }
            return encoded.ToString();
        }

        /// <summary>
        /// Generates the X-Bogus signature for a TikTok API request.
        /// 
        /// Builds an 18-byte payload containing:
        ///   - Header byte (0x40) and RC4 key bytes [0x00, 0x01, 0x0E]
        ///   - Last 2 bytes of MD5(MD5(query))
        ///   - Last 2 bytes of MD5(MD5(body))
        ///   - Last 2 bytes of MD5(Base64(RC4(userAgent)))
        ///   - 4-byte big-endian timestamp (seconds)
        ///   - 4-byte big-endian canvas fingerprint value
        /// 
        /// Appends an XOR checksum byte, RC4-encrypts with key [0xFF],
        /// prepends a 2-byte header [0x02, 0xFF], and custom-base64 encodes the result.
        /// </summary>
        /// <param name="query">The full URL query string to sign.</param>
        /// <param name="userAgent">The browser User-Agent string.</param>
        /// <param name="canvasValue">Canvas fingerprint value (browser-dependent).</param>
        /// <param name="body">The request body string. Empty string if no body.</param>
        /// <param name="timestampMs">Unix timestamp in milliseconds. Uses current time if null.</param>
        /// <returns>The X-Bogus token string.</returns>
        public static string Encrypt(string query, string userAgent, uint canvasValue, string body = "", long? timestampMs = null)
        {
            byte[] rc4Key = { 0x00, 0x01, 0x0E };
            string bodyMd5Hex = "d41d8cd98f00b204e9800998ecf8427e"; // MD5 of empty string

            byte[] queryDoubleHash = HexStringToBytes(ComputeMd5Hex(HexStringToBytes(ComputeMd5Hex(query))));

            if (!string.IsNullOrEmpty(body))
                bodyMd5Hex = ComputeMd5Hex(body);
            byte[] bodyDoubleHash = HexStringToBytes(ComputeMd5Hex(HexStringToBytes(bodyMd5Hex)));

            var payload = new List<byte>();
            payload.Add(0x40);
            payload.AddRange(rc4Key);
            payload.Add(queryDoubleHash[queryDoubleHash.Length - 2]);
            payload.Add(queryDoubleHash[queryDoubleHash.Length - 1]);
            payload.Add(bodyDoubleHash[bodyDoubleHash.Length - 2]);
            payload.Add(bodyDoubleHash[bodyDoubleHash.Length - 1]);

            byte[] encryptedUserAgent = Rc4Encrypt(rc4Key, Encoding.UTF8.GetBytes(userAgent));
            string userAgentToken = CustomBase64Encode(encryptedUserAgent, StandardBase64Alphabet);
            byte[] userAgentTokenHash = HexStringToBytes(ComputeMd5Hex(userAgentToken));
            payload.Add(userAgentTokenHash[userAgentTokenHash.Length - 2]);
            payload.Add(userAgentTokenHash[userAgentTokenHash.Length - 1]);

            long currentTimestampMs = timestampMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            uint timestampSeconds = (uint)(currentTimestampMs / 1000);
            payload.Add((byte)((timestampSeconds >> 24) & 0xFF));
            payload.Add((byte)((timestampSeconds >> 16) & 0xFF));
            payload.Add((byte)((timestampSeconds >> 8) & 0xFF));
            payload.Add((byte)(timestampSeconds & 0xFF));

            payload.Add((byte)((canvasValue >> 24) & 0xFF));
            payload.Add((byte)((canvasValue >> 16) & 0xFF));
            payload.Add((byte)((canvasValue >> 8) & 0xFF));
            payload.Add((byte)(canvasValue & 0xFF));

            byte[] payloadBytes = payload.ToArray();
            int xorChecksum = 0;
            foreach (byte b in payloadBytes)
                xorChecksum ^= b;

            byte[] payloadWithChecksum = new byte[payloadBytes.Length + 1];
            Array.Copy(payloadBytes, payloadWithChecksum, payloadBytes.Length);
            payloadWithChecksum[payloadBytes.Length] = (byte)(xorChecksum & 0xFF);

            byte[] encryptedPayload = Rc4Encrypt(new byte[] { 0xFF }, payloadWithChecksum);

            byte[] finalOutput = new byte[2 + encryptedPayload.Length];
            finalOutput[0] = 0x02;
            finalOutput[1] = 0xFF;
            Array.Copy(encryptedPayload, 0, finalOutput, 2, encryptedPayload.Length);

            return CustomBase64Encode(finalOutput, CustomBase64Alphabet);
        }

        /// <summary>
        /// Convenience alias for <see cref="Encrypt"/>. Generates the X-Bogus signature token.
        /// </summary>
        public static string Sign(string query, string userAgent, uint canvasValue, string body = "", long? timestampMs = null)
        {
            return Encrypt(query, userAgent, canvasValue, body, timestampMs);
        }
    }
}

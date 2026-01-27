using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace TikTokWeb
{
    public class Gnarly
    {
        private static readonly uint?[] Constants = new uint?[]
        {
            0xFFFFFFFF, 138, 1498001188, 211147047, 253, null, 203, 288, 9,
            1196819126, 3212677781, 135, 263, 193, 58, 18, 244, 2931180889, 240, 173,
            268, 2157053261, 261, 175, 14, 5, 171, 270, 156, 258, 13, 15, 3732962506,
            185, 169, 2, 6, 132, 162, 200, 3, 160, 217618912, 62, 2517678443, 44, 164,
            4, 96, 183, 2903579748, 3863347763, 119, 181, 10, 190, 8, 2654435769, 259,
            104, 230, 128, 2633865432, 225, 1, 257, 143, 179, 16, 600974999, 185100057,
            32, 188, 53, 2718276124, 177, 196, 4294967296, 147, 117, 17, 49, 7, 28, 12,
            266, 216, 11, 0, 45, 166, 247, 1451689750
        };

        private static readonly uint[] ChachaInitVector = new uint[]
        {
            Constants[9].Value, Constants[69].Value, Constants[51].Value, Constants[92].Value
        };

        private uint[] _chachaState;
        private int _stateIndex;
        private readonly Random _random;

        public Gnarly() : this(new Random()) { }

        public Gnarly(Random random)
        {
            _random = random;
            InitializePrngState();
        }

        private static uint ToUInt32(long value)
        {
            return (uint)(value & 0xFFFFFFFF);
        }

        private static uint RotateLeft(uint value, int bits)
        {
            return ToUInt32((value << bits) | (value >> (32 - bits)));
        }

        private void InitializePrngState()
        {
            long currentTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _chachaState = new uint[]
            {
                Constants[44].Value, Constants[74].Value, Constants[10].Value, Constants[62].Value,
                Constants[42].Value, Constants[17].Value, Constants[2].Value, Constants[21].Value,
                Constants[3].Value, Constants[70].Value, Constants[50].Value, Constants[32].Value,
                ToUInt32(Constants[0].Value & currentTimeMs),
                (uint)_random.Next((int)Constants[77].Value),
                (uint)_random.Next((int)Constants[77].Value),
                (uint)_random.Next((int)Constants[77].Value)
            };
            _stateIndex = (int)Constants[88].Value;
        }

        private static void QuarterRound(uint[] state, int a, int b, int c, int d)
        {
            state[a] = ToUInt32(state[a] + state[b]); state[d] = RotateLeft(state[d] ^ state[a], 16);
            state[c] = ToUInt32(state[c] + state[d]); state[b] = RotateLeft(state[b] ^ state[c], 12);
            state[a] = ToUInt32(state[a] + state[b]); state[d] = RotateLeft(state[d] ^ state[a], 8);
            state[c] = ToUInt32(state[c] + state[d]); state[b] = RotateLeft(state[b] ^ state[c], 7);
        }

        private static uint[] ChachaBlock(uint[] state, int rounds)
        {
            uint[] workingState = (uint[])state.Clone();
            int roundCount = 0;
            while (roundCount < rounds)
            {
                QuarterRound(workingState, 0, 4, 8, 12); QuarterRound(workingState, 1, 5, 9, 13);
                QuarterRound(workingState, 2, 6, 10, 14); QuarterRound(workingState, 3, 7, 11, 15);
                roundCount++;
                if (roundCount >= rounds)
                    break;
                QuarterRound(workingState, 0, 5, 10, 15); QuarterRound(workingState, 1, 6, 11, 12);
                QuarterRound(workingState, 2, 7, 12, 13); QuarterRound(workingState, 3, 4, 13, 14);
                roundCount++;
            }
            for (int i = 0; i < 16; i++)
            {
                workingState[i] = ToUInt32(workingState[i] + state[i]);
            }
            return workingState;
        }

        private static void IncrementCounter(uint[] state)
        {
            state[12] = ToUInt32(state[12] + 1);
        }

        private double GenerateRandomDouble()
        {
            uint[] chachaOutput = ChachaBlock(_chachaState, 8);
            uint lowBits = chachaOutput[_stateIndex];
            uint highBits = (chachaOutput[_stateIndex + 8] & 0xFFFFFFF0) >> 11;
            if (_stateIndex == 7)
            {
                IncrementCounter(_chachaState);
                _stateIndex = 0;
            }
            else
            {
                _stateIndex++;
            }
            return (lowBits + 4294967296.0 * highBits) / Math.Pow(2, 53);
        }

        private static List<int> IntegerToBytes(long value)
        {
            if (value < 255 * 255)
            {
                return new List<int> { (int)((value >> 8) & 0xFF), (int)(value & 0xFF) };
            }
            return new List<int>
            {
                (int)((value >> 24) & 0xFF),
                (int)((value >> 16) & 0xFF),
                (int)((value >> 8) & 0xFF),
                (int)(value & 0xFF)
            };
        }

        private static uint StringToBigEndianInt(string input)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(input);
            int length = Math.Min(buffer.Length, 4);
            uint accumulator = 0;
            for (int i = 0; i < length; i++)
            {
                accumulator = (accumulator << 8) | buffer[i];
            }
            return ToUInt32(accumulator);
        }

        private static void ChachaEncryptData(uint[] keyWords, int rounds, byte[] data)
        {
            int fullWordCount = data.Length / 4;
            int remainingBytes = data.Length % 4;
            uint[] dataWords = new uint[(data.Length + 3) / 4];

            for (int i = 0; i < fullWordCount; i++)
            {
                int byteIndex = 4 * i;
                dataWords[i] = (uint)(data[byteIndex] | (data[byteIndex + 1] << 8) | (data[byteIndex + 2] << 16) | (data[byteIndex + 3] << 24));
            }

            if (remainingBytes > 0)
            {
                uint partialWord = 0;
                int baseIndex = 4 * fullWordCount;
                for (int c = 0; c < remainingBytes; c++)
                {
                    partialWord |= (uint)(data[baseIndex + c] << (8 * c));
                }
                dataWords[fullWordCount] = partialWord;
            }

            int wordOffset = 0;
            uint[] encryptionState = (uint[])keyWords.Clone();
            while (wordOffset + 16 < dataWords.Length)
            {
                uint[] keyStream = ChachaBlock(encryptionState, rounds);
                IncrementCounter(encryptionState);
                for (int k = 0; k < 16; k++)
                {
                    dataWords[wordOffset + k] ^= keyStream[k];
                }
                wordOffset += 16;
            }

            int remainingWords = dataWords.Length - wordOffset;
            uint[] finalKeyStream = ChachaBlock(encryptionState, rounds);
            for (int k = 0; k < remainingWords; k++)
            {
                dataWords[wordOffset + k] ^= finalKeyStream[k];
            }

            for (int i = 0; i < fullWordCount; i++)
            {
                uint word = dataWords[i];
                int byteIndex = 4 * i;
                data[byteIndex] = (byte)(word & 0xFF);
                data[byteIndex + 1] = (byte)((word >> 8) & 0xFF);
                data[byteIndex + 2] = (byte)((word >> 16) & 0xFF);
                data[byteIndex + 3] = (byte)((word >> 24) & 0xFF);
            }

            if (remainingBytes > 0)
            {
                uint word = dataWords[fullWordCount];
                int baseIndex = 4 * fullWordCount;
                for (int c = 0; c < remainingBytes; c++)
                {
                    data[baseIndex + c] = (byte)((word >> (8 * c)) & 0xFF);
                }
            }
        }

        private static string ChachaEncryptString(uint[] keyWords, int rounds, string input)
        {
            uint[] state = new uint[16];
            Array.Copy(ChachaInitVector, 0, state, 0, 4);
            Array.Copy(keyWords, 0, state, 4, 12);

            byte[] data = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                data[i] = (byte)input[i];
            }

            ChachaEncryptData(state, rounds, data);

            var result = new StringBuilder();
            foreach (byte byteValue in data)
            {
                result.Append((char)byteValue);
            }
            return result.ToString();
        }

        public string Encrypt(string queryString, string body, string userAgent, int envcode = 0, string version = "5.1.1", long? timestampMs = null)
        {
            long actualTimestampMs = timestampMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var signatureData = new Dictionary<int, object>();
            signatureData[1] = 1;
            signatureData[2] = envcode;
            signatureData[3] = ComputeMd5Hex(queryString);
            signatureData[4] = ComputeMd5Hex(body);
            signatureData[5] = ComputeMd5Hex(userAgent);
            signatureData[6] = actualTimestampMs / 1000;
            signatureData[7] = 1508145731;
            signatureData[8] = (actualTimestampMs * 1000) % 2147483648;
            signatureData[9] = version;

            if (version == "5.1.1")
            {
                signatureData[10] = "1.0.0.314";
                signatureData[11] = 1;
                uint checksumValue = 0;
                for (int i = 1; i < 12; i++)
                {
                    object value = signatureData[i];
                    uint xorValue = value is int intVal ? (uint)intVal : (value is long longVal ? (uint)longVal : StringToBigEndianInt(value.ToString()));
                    checksumValue ^= xorValue;
                }
                signatureData[12] = checksumValue & 0xFFFFFFFF;
            }
            else if (version != "5.1.0")
            {
                throw new Exception("Unsupported version");
            }

            uint headerChecksum = 0;
            foreach (var value in signatureData.Values)
            {
                if (value is int intVal)
                    headerChecksum ^= (uint)intVal;
                else if (value is long longVal)
                    headerChecksum ^= (uint)longVal;
                else if (value is uint uintVal)
                    headerChecksum ^= uintVal;
            }
            signatureData[0] = headerChecksum & 0xFFFFFFFF;

            var payloadBytes = new List<int>();
            payloadBytes.Add(signatureData.Count);

            foreach (var keyValuePair in signatureData)
            {
                payloadBytes.Add(keyValuePair.Key);
                List<int> valueBytes;
                if (keyValuePair.Value is int intVal)
                {
                    valueBytes = IntegerToBytes(intVal);
                }
                else if (keyValuePair.Value is long longVal)
                {
                    valueBytes = IntegerToBytes(longVal);
                }
                else if (keyValuePair.Value is uint uintVal)
                {
                    valueBytes = IntegerToBytes(uintVal);
                }
                else
                {
                    byte[] stringBytes = Encoding.UTF8.GetBytes(keyValuePair.Value.ToString());
                    valueBytes = new List<int>();
                    foreach (byte byteValue in stringBytes)
                    {
                        valueBytes.Add(byteValue);
                    }
                }
                payloadBytes.AddRange(IntegerToBytes(valueBytes.Count));
                payloadBytes.AddRange(valueBytes);
            }

            var payloadString = new StringBuilder();
            foreach (int byteValue in payloadBytes)
            {
                payloadString.Append((char)byteValue);
            }

            uint[] encryptionKeyWords = new uint[12];
            var encryptionKeyBytes = new List<byte>();
            int roundAccumulator = 0;

            for (int i = 0; i < 12; i++)
            {
                double randomValue = GenerateRandomDouble();
                uint keyWord = ToUInt32((long)(randomValue * 4294967296.0));
                encryptionKeyWords[i] = keyWord;
                roundAccumulator = (roundAccumulator + (int)(keyWord & 15)) & 15;
                encryptionKeyBytes.Add((byte)(keyWord & 0xFF));
                encryptionKeyBytes.Add((byte)((keyWord >> 8) & 0xFF));
                encryptionKeyBytes.Add((byte)((keyWord >> 16) & 0xFF));
                encryptionKeyBytes.Add((byte)((keyWord >> 24) & 0xFF));
            }

            int encryptionRounds = roundAccumulator + 5;
            string encryptedPayload = ChachaEncryptString(encryptionKeyWords, encryptionRounds, payloadString.ToString());

            int keyInsertPosition = 0;
            foreach (byte byteValue in encryptionKeyBytes)
            {
                keyInsertPosition = (keyInsertPosition + byteValue) % (encryptedPayload.Length + 1);
            }
            foreach (char character in encryptedPayload)
            {
                keyInsertPosition = (keyInsertPosition + character) % (encryptedPayload.Length + 1);
            }

            var keyBytesString = new StringBuilder();
            foreach (byte byteValue in encryptionKeyBytes)
            {
                keyBytesString.Append((char)byteValue);
            }

            string finalPayload = (char)(((1 << 6) ^ (1 << 3) ^ 3) & 0xFF) + encryptedPayload.Substring(0, keyInsertPosition) + keyBytesString.ToString() + encryptedPayload.Substring(keyInsertPosition);

            const string base64Alphabet = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP=";
            var encodedOutput = new StringBuilder();
            int fullBlockLength = (finalPayload.Length / 3) * 3;

            for (int i = 0; i < fullBlockLength; i += 3)
            {
                int block = (finalPayload[i] << 16) | (finalPayload[i + 1] << 8) | finalPayload[i + 2];
                encodedOutput.Append(base64Alphabet[(block >> 18) & 63]);
                encodedOutput.Append(base64Alphabet[(block >> 12) & 63]);
                encodedOutput.Append(base64Alphabet[(block >> 6) & 63]);
                encodedOutput.Append(base64Alphabet[block & 63]);
            }

            return encodedOutput.ToString();
        }

        private static string ComputeMd5Hex(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                var hexString = new StringBuilder();
                foreach (byte byteValue in hash)
                {
                    hexString.Append(byteValue.ToString("x2"));
                }
                return hexString.ToString();
            }
        }

        public string Sign(string queryString, string body, string userAgent, int seed = 0, string version = "5.1.1", long? timestampMs = null)
        {
            return Encrypt(queryString, body, userAgent, seed, version, timestampMs);
        }
    }
}

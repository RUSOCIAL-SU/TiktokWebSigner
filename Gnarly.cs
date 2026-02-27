using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace TikTokWeb
{
    /// <summary>
    /// Generates the X-Gnarly signature token for TikTok web API requests.
    /// Serializes request metadata (query/body/UA hashes, timestamp, canvas, version) into a
    /// binary payload, encrypts it with a ChaCha-based cipher using PRNG-derived keys,
    /// interleaves the key material, and encodes the result with a custom base64 alphabet.
    /// Supports SDK versions 5.1.0, 5.1.1, and 5.1.2.
    /// </summary>
    public class Gnarly
    {
        /// <summary>
        /// Lookup table of obfuscated numeric constants used throughout the algorithm.
        /// Indices are referenced by the PRNG seed, ChaCha IV, and other operations.
        /// Index 5 and 77 are null (index 77 = 2^32, exceeds uint range; handled separately).
        /// </summary>
        private static readonly uint?[] CryptoConstants = new uint?[]
        {
            0xFFFFFFFF, 138, 1498001188, 211147047, 253, null, 203, 288, 9,
            1196819126, 3212677781, 135, 263, 193, 58, 18, 244, 2931180889, 240, 173,
            268, 2157053261, 261, 175, 14, 5, 171, 270, 156, 258, 13, 15, 3732962506,
            185, 169, 2, 6, 132, 162, 200, 3, 160, 217618912, 62, 2517678443, 44, 164,
            4, 96, 183, 2903579748, 3863347763, 119, 181, 10, 190, 8, 2654435769, 259,
            104, 230, 128, 2633865432, 225, 1, 257, 143, 179, 16, 600974999, 185100057,
            32, 188, 53, 2718276124, 177, 196, null, 147, 117, 17, 49, 7, 28, 12,
            266, 216, 11, 0, 45, 166, 247, 1451689750
        };

        /// <summary>
        /// ChaCha initial state vector (4 words), derived from CryptoConstants at indices [9, 69, 51, 92].
        /// Prepended to the 12-word encryption key to form the full 16-word ChaCha state.
        /// </summary>
        private static readonly uint[] ChachaInitialState = new uint[]
        {
            CryptoConstants[9].Value, CryptoConstants[69].Value,
            CryptoConstants[51].Value, CryptoConstants[92].Value
        };

        private uint[] _prngState;
        private int _prngStateIndex;
        private readonly Random _random;

        /// <summary>
        /// Creates a new Gnarly instance with a default Random for PRNG seeding.
        /// </summary>
        public Gnarly() : this(new Random()) { }

        /// <summary>
        /// Creates a new Gnarly instance with a provided Random for deterministic testing.
        /// Initializes the internal ChaCha-based PRNG state on construction.
        /// </summary>
        /// <param name="random">Random instance used to seed the ChaCha PRNG state.</param>
        public Gnarly(Random random)
        {
            _random = random;
            InitializePrngState();
        }

        /// <summary>
        /// Masks a 64-bit value down to 32 bits, equivalent to (uint)(value &amp; 0xFFFFFFFF).
        /// </summary>
        private static uint MaskTo32Bits(long value)
        {
            return (uint)(value & 0xFFFFFFFF);
        }

        /// <summary>
        /// Performs a 32-bit left rotation: bits that shift past bit 31 wrap to the low end.
        /// </summary>
        private static uint RotateLeft32(uint value, int shiftAmount)
        {
            return MaskTo32Bits((value << shiftAmount) | (value >> (32 - shiftAmount)));
        }

        /// <summary>
        /// Generates a uniformly distributed random uint32 (0 to 4,294,967,295)
        /// using 4 random bytes. Replaces the Python <c>random.randint(0, 2^32 - 1)</c>.
        /// </summary>
        private uint GenerateRandomUInt32()
        {
            byte[] buffer = new byte[4];
            _random.NextBytes(buffer);
            return BitConverter.ToUInt32(buffer, 0);
        }

        /// <summary>
        /// Seeds the 16-word ChaCha PRNG state array.
        /// Words 0-11 come from fixed CryptoConstants entries, word 12 is the current
        /// timestamp masked to 32 bits, and words 13-15 are random uint32 values.
        /// Also sets the initial state index from CryptoConstants[88] (= 0).
        /// </summary>
        private void InitializePrngState()
        {
            long currentTimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _prngState = new uint[]
            {
                CryptoConstants[44].Value, CryptoConstants[74].Value, CryptoConstants[10].Value, CryptoConstants[62].Value,
                CryptoConstants[42].Value, CryptoConstants[17].Value, CryptoConstants[2].Value,  CryptoConstants[21].Value,
                CryptoConstants[3].Value,  CryptoConstants[70].Value, CryptoConstants[50].Value, CryptoConstants[32].Value,
                MaskTo32Bits(CryptoConstants[0].Value & currentTimestampMs),
                GenerateRandomUInt32(),
                GenerateRandomUInt32(),
                GenerateRandomUInt32()
            };
            _prngStateIndex = (int)CryptoConstants[88].Value;
        }

        /// <summary>
        /// Performs one ChaCha quarter-round on four words of the state array.
        /// Applies the add-XOR-rotate pattern with shifts of 16, 12, 8, and 7 bits.
        /// </summary>
        private static void ChachaQuarterRound(uint[] state, int a, int b, int c, int d)
        {
            state[a] = MaskTo32Bits(state[a] + state[b]); state[d] = RotateLeft32(state[d] ^ state[a], 16);
            state[c] = MaskTo32Bits(state[c] + state[d]); state[b] = RotateLeft32(state[b] ^ state[c], 12);
            state[a] = MaskTo32Bits(state[a] + state[b]); state[d] = RotateLeft32(state[d] ^ state[a], 8);
            state[c] = MaskTo32Bits(state[c] + state[d]); state[b] = RotateLeft32(state[b] ^ state[c], 7);
        }

        /// <summary>
        /// Executes the ChaCha block function: clones the input state, applies alternating
        /// column and diagonal quarter-rounds for the given number of rounds, then adds
        /// the original state back in (mod 2^32). Returns the resulting 16-word keystream block.
        /// </summary>
        private static uint[] ComputeChachaBlock(uint[] initialState, int rounds)
        {
            uint[] workingState = (uint[])initialState.Clone();
            int completedRounds = 0;
            while (completedRounds < rounds)
            {
                ChachaQuarterRound(workingState, 0, 4, 8, 12);
                ChachaQuarterRound(workingState, 1, 5, 9, 13);
                ChachaQuarterRound(workingState, 2, 6, 10, 14);
                ChachaQuarterRound(workingState, 3, 7, 11, 15);
                completedRounds++;
                if (completedRounds >= rounds)
                    break;
                ChachaQuarterRound(workingState, 0, 5, 10, 15);
                ChachaQuarterRound(workingState, 1, 6, 11, 12);
                ChachaQuarterRound(workingState, 2, 7, 12, 13);
                ChachaQuarterRound(workingState, 3, 4, 13, 14);
                completedRounds++;
            }
            for (int i = 0; i < 16; i++)
            {
                workingState[i] = MaskTo32Bits(workingState[i] + initialState[i]);
            }
            return workingState;
        }

        /// <summary>
        /// Increments word 12 (the counter) of a ChaCha state array by 1 (mod 2^32).
        /// </summary>
        private static void IncrementChachaCounter(uint[] state)
        {
            state[12] = MaskTo32Bits(state[12] + 1);
        }

        /// <summary>
        /// Produces a random double in [0, 1) using the internal ChaCha-based PRNG.
        /// Consumes one entry from the current ChaCha block output; when all 8 entries
        /// in the current block are used, increments the counter and resets the index.
        /// The result has 53 bits of precision (matching JavaScript's Math.random()).
        /// </summary>
        private double GenerateRandomFloat()
        {
            uint[] blockOutput = ComputeChachaBlock(_prngState, 8);
            uint lowBits = blockOutput[_prngStateIndex];
            uint highBits = (blockOutput[_prngStateIndex + 8] & 0xFFFFFFF0) >> 11;

            if (_prngStateIndex == 7)
            {
                IncrementChachaCounter(_prngState);
                _prngStateIndex = 0;
            }
            else
            {
                _prngStateIndex++;
            }

            return (lowBits + 4294967296.0 * highBits) / Math.Pow(2, 53);
        }

        /// <summary>
        /// Serializes an integer into big-endian bytes.
        /// Values below 65025 (255*255) produce 2 bytes; larger values produce 4 bytes.
        /// Used for both field values and length prefixes in the binary payload.
        /// </summary>
        private static List<int> ConvertIntToBytes(long value)
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

        /// <summary>
        /// Converts the first 4 UTF-8 bytes of a string into a big-endian uint32.
        /// Used to XOR string field values into the version-specific checksum.
        /// </summary>
        private static uint ConvertStringToUInt32BigEndian(string input)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(input);
            int length = Math.Min(buffer.Length, 4);
            uint accumulator = 0;
            for (int i = 0; i < length; i++)
            {
                accumulator = (accumulator << 8) | buffer[i];
            }
            return MaskTo32Bits(accumulator);
        }

        /// <summary>
        /// Encrypts a byte array in-place using ChaCha in CTR mode.
        /// Converts the data to little-endian 32-bit words, XORs each 16-word block
        /// with a ChaCha keystream block (incrementing the counter between blocks),
        /// then converts back to bytes.
        /// </summary>
        private static void ChachaEncryptBytes(uint[] chachaState, int rounds, byte[] data)
        {
            int fullWordCount = data.Length / 4;
            int trailingByteCount = data.Length % 4;
            uint[] dataAsWords = new uint[(data.Length + 3) / 4];

            for (int i = 0; i < fullWordCount; i++)
            {
                int offset = 4 * i;
                dataAsWords[i] = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
            }

            if (trailingByteCount > 0)
            {
                uint partialWord = 0;
                int baseOffset = 4 * fullWordCount;
                for (int b = 0; b < trailingByteCount; b++)
                {
                    partialWord |= (uint)(data[baseOffset + b] << (8 * b));
                }
                dataAsWords[fullWordCount] = partialWord;
            }

            int wordPosition = 0;
            uint[] ctrState = (uint[])chachaState.Clone();

            while (wordPosition + 16 < dataAsWords.Length)
            {
                uint[] keystream = ComputeChachaBlock(ctrState, rounds);
                IncrementChachaCounter(ctrState);
                for (int k = 0; k < 16; k++)
                {
                    dataAsWords[wordPosition + k] ^= keystream[k];
                }
                wordPosition += 16;
            }

            int remainingWordCount = dataAsWords.Length - wordPosition;
            uint[] finalKeystream = ComputeChachaBlock(ctrState, rounds);
            for (int k = 0; k < remainingWordCount; k++)
            {
                dataAsWords[wordPosition + k] ^= finalKeystream[k];
            }

            for (int i = 0; i < fullWordCount; i++)
            {
                uint word = dataAsWords[i];
                int offset = 4 * i;
                data[offset] = (byte)(word & 0xFF);
                data[offset + 1] = (byte)((word >> 8) & 0xFF);
                data[offset + 2] = (byte)((word >> 16) & 0xFF);
                data[offset + 3] = (byte)((word >> 24) & 0xFF);
            }

            if (trailingByteCount > 0)
            {
                uint word = dataAsWords[fullWordCount];
                int baseOffset = 4 * fullWordCount;
                for (int b = 0; b < trailingByteCount; b++)
                {
                    data[baseOffset + b] = (byte)((word >> (8 * b)) & 0xFF);
                }
            }
        }

        /// <summary>
        /// Encrypts a string using ChaCha in CTR mode.
        /// Builds the full 16-word ChaCha state from the 4-word IV + 12-word key,
        /// treats each character as a single byte, encrypts in-place, and returns
        /// the result as a string of single-byte characters.
        /// </summary>
        private static string ChachaEncryptString(uint[] keyWords, int rounds, string plaintext)
        {
            uint[] fullState = new uint[16];
            Array.Copy(ChachaInitialState, 0, fullState, 0, 4);
            Array.Copy(keyWords, 0, fullState, 4, 12);

            byte[] data = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++)
            {
                data[i] = (byte)plaintext[i];
            }

            ChachaEncryptBytes(fullState, rounds, data);

            var result = new StringBuilder(data.Length);
            foreach (byte b in data)
            {
                result.Append((char)b);
            }
            return result.ToString();
        }

        /// <summary>
        /// Computes the MD5 hash of a UTF-8 string and returns it as a 32-char lowercase hex string.
        /// </summary>
        private static string ComputeMd5Hex(string input)
        {
            return Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(input)));
        }

        /// <summary>
        /// Generates the X-Gnarly signature for a TikTok API request.
        /// 
        /// Process:
        ///   1. Builds a field map with MD5 hashes of query/body/UA, timestamp, canvas,
        ///      version info, and version-specific checksums (fields 0-12).
        ///   2. Serializes the field map into a length-prefixed binary payload
        ///      (field key + value length + value bytes for each field).
        ///   3. Generates 12 random uint32 key words via the ChaCha PRNG, derives
        ///      the encryption round count from the low nibbles.
        ///   4. ChaCha-encrypts the serialized payload.
        ///   5. Interleaves the 48-byte key material into the encrypted data at a
        ///      deterministic insertion point, prepends a 1-byte header.
        ///   6. Encodes the final byte sequence with a custom base64 alphabet.
        /// </summary>
        /// <param name="queryString">The full URL query string to sign.</param>
        /// <param name="body">The request body string. Use empty string if no body.</param>
        /// <param name="userAgent">The browser User-Agent string.</param>
        /// <param name="canvasValue">Canvas fingerprint value (default 1938040196 for web).</param>
        /// <param name="version">SDK version string: "5.1.0", "5.1.1", or "5.1.2".</param>
        /// <param name="timestampMs">Unix timestamp in milliseconds. Uses current time if null.</param>
        /// <returns>The X-Gnarly token string (~286 characters).</returns>
        public string Encrypt(string queryString, string body, string userAgent, uint canvasValue = 1938040196, string version = "5.1.2", long? timestampMs = null)
        {
            long currentTimestampMs = timestampMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var fieldMap = new Dictionary<int, object>();
            var fieldOrder = new List<int>();

            void AddField(int fieldId, object fieldValue)
            {
                fieldMap[fieldId] = fieldValue;
                if (!fieldOrder.Contains(fieldId))
                    fieldOrder.Add(fieldId);
            }

            AddField(1, 1L);
            AddField(2, 14L);
            AddField(3, ComputeMd5Hex(queryString));
            AddField(4, ComputeMd5Hex(body));
            AddField(5, ComputeMd5Hex(userAgent));
            AddField(6, currentTimestampMs / 1000);
            AddField(7, (long)canvasValue);
            AddField(8, currentTimestampMs % 2147483648);
            AddField(9, version);

            if (version == "5.1.1")
            {
                AddField(10, "1.0.0.314");
                AddField(11, 1L);
                uint versionChecksum = 0;
                for (int i = 1; i < 12; i++)
                {
                    object fieldValue = fieldMap[i];
                    uint xorValue = fieldValue is long numericValue ? (uint)numericValue : ConvertStringToUInt32BigEndian(fieldValue.ToString());
                    versionChecksum ^= xorValue;
                }
                AddField(12, (long)(versionChecksum & 0xFFFFFFFF));
            }
            else if (version == "5.1.2")
            {
                AddField(10, "1.0.0.316");
                AddField(11, 1L);
                uint versionChecksum = 0;
                for (int i = 1; i < 12; i++)
                {
                    object fieldValue = fieldMap[i];
                    uint xorValue = fieldValue is long numericValue ? (uint)numericValue : ConvertStringToUInt32BigEndian(fieldValue.ToString());
                    versionChecksum ^= xorValue;
                }
                AddField(12, (long)(versionChecksum & 0xFFFFFFFF));
            }
            else if (version != "5.1.0")
            {
                throw new Exception($"Unsupported version: {version}");
            }

            long globalChecksum = 0;
            foreach (int fieldId in fieldOrder)
            {
                object fieldValue = fieldMap[fieldId];
                if (fieldValue is long numericValue)
                    globalChecksum ^= numericValue;
            }
            AddField(0, globalChecksum & 0xFFFFFFFF);

            // Serialize field map into a binary payload: [fieldCount, (fieldId, valueLen, valueBytes)...]
            var serializedBytes = new List<int>();
            serializedBytes.Add(fieldOrder.Count);

            foreach (int fieldId in fieldOrder)
            {
                object fieldValue = fieldMap[fieldId];
                serializedBytes.Add(fieldId);

                List<int> valueBytes;
                if (fieldValue is long numericValue)
                {
                    valueBytes = ConvertIntToBytes(numericValue);
                }
                else
                {
                    byte[] utf8Bytes = Encoding.UTF8.GetBytes(fieldValue.ToString());
                    valueBytes = new List<int>(utf8Bytes.Length);
                    foreach (byte b in utf8Bytes)
                    {
                        valueBytes.Add(b);
                    }
                }
                serializedBytes.AddRange(ConvertIntToBytes(valueBytes.Count));
                serializedBytes.AddRange(valueBytes);
            }

            var serializedPayload = new StringBuilder(serializedBytes.Count);
            foreach (int byteValue in serializedBytes)
            {
                serializedPayload.Append((char)byteValue);
            }

            // Generate 12 random ChaCha key words and derive encryption round count
            uint[] chachaKeyWords = new uint[12];
            var chachaKeyBytes = new List<byte>(48);
            int roundCounter = 0;

            for (int i = 0; i < 12; i++)
            {
                double randomFloat = GenerateRandomFloat();
                uint keyWord = MaskTo32Bits((long)(randomFloat * 4294967296.0));
                chachaKeyWords[i] = keyWord;
                roundCounter = (roundCounter + (int)(keyWord & 15)) & 15;
                chachaKeyBytes.Add((byte)(keyWord & 0xFF));
                chachaKeyBytes.Add((byte)((keyWord >> 8) & 0xFF));
                chachaKeyBytes.Add((byte)((keyWord >> 16) & 0xFF));
                chachaKeyBytes.Add((byte)((keyWord >> 24) & 0xFF));
            }

            int encryptionRounds = roundCounter + 5;
            string encryptedData = ChachaEncryptString(chachaKeyWords, encryptionRounds, serializedPayload.ToString());

            // Compute a deterministic insertion point for interleaving key bytes into encrypted data
            int keyInsertionIndex = 0;
            foreach (byte b in chachaKeyBytes)
            {
                keyInsertionIndex = (keyInsertionIndex + b) % (encryptedData.Length + 1);
            }
            foreach (char c in encryptedData)
            {
                keyInsertionIndex = (keyInsertionIndex + c) % (encryptedData.Length + 1);
            }

            var keyAsString = new StringBuilder(48);
            foreach (byte b in chachaKeyBytes)
            {
                keyAsString.Append((char)b);
            }

            // Assemble: header byte + encrypted[:insertionPoint] + keyBytes + encrypted[insertionPoint:]
            char headerByte = (char)(((1 << 6) ^ (1 << 3) ^ 3) & 0xFF);
            string assembledPayload = headerByte
                + encryptedData.Substring(0, keyInsertionIndex)
                + keyAsString.ToString()
                + encryptedData.Substring(keyInsertionIndex);

            // Custom base64 encode the final assembled payload
            const string gnarlyBase64Alphabet = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP=";
            var encodedToken = new StringBuilder();
            int fullBlockLength = (assembledPayload.Length / 3) * 3;

            for (int i = 0; i < fullBlockLength; i += 3)
            {
                int threeByteBlock = (assembledPayload[i] << 16) | (assembledPayload[i + 1] << 8) | assembledPayload[i + 2];
                encodedToken.Append(gnarlyBase64Alphabet[(threeByteBlock >> 18) & 63]);
                encodedToken.Append(gnarlyBase64Alphabet[(threeByteBlock >> 12) & 63]);
                encodedToken.Append(gnarlyBase64Alphabet[(threeByteBlock >> 6) & 63]);
                encodedToken.Append(gnarlyBase64Alphabet[threeByteBlock & 63]);
            }

            return encodedToken.ToString();
        }

        /// <summary>
        /// Convenience alias for <see cref="Encrypt"/>. Generates the X-Gnarly signature token.
        /// </summary>
        public string Sign(string queryString, string body, string userAgent, uint canvasValue = 1938040196, string version = "5.1.2", long? timestampMs = null)
        {
            return Encrypt(queryString, body, userAgent, canvasValue, version, timestampMs);
        }
    }
}

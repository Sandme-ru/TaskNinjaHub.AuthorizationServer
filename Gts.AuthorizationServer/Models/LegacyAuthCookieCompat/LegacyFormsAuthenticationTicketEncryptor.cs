using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class LegacyFormsAuthenticationTicketEncryptor.
/// </summary>
public class LegacyFormsAuthenticationTicketEncryptor
{
    /// <summary>
    /// The default hash algorithm
    /// </summary>
    private const ShaVersion DefaultHashAlgorithm = ShaVersion.Sha1;

    /// <summary>
    /// The default compatibility mode
    /// </summary>
    private const CompatibilityMode DefaultCompatibilityMode = CompatibilityMode.Framework20SP2;

    /// <summary>
    /// The random number generator
    /// </summary>
    private static RandomNumberGenerator _randomNumberGenerator;

    /// <summary>
    /// The decryption key BLOB
    /// </summary>
    private byte[] _decryptionKeyBlob;

    /// <summary>
    /// The compatibility mode
    /// </summary>
    private CompatibilityMode _compatibilityMode;

    /// <summary>
    /// The hasher
    /// </summary>
    private HashProvider _hasher;

    /// <summary>
    /// Gets the random number generator.
    /// </summary>
    /// <value>The random number generator.</value>
    private static RandomNumberGenerator RandomNumberGenerator
    {
        get
        {
            if (_randomNumberGenerator == null)
                _randomNumberGenerator = RandomNumberGenerator.Create();

            return _randomNumberGenerator;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LegacyFormsAuthenticationTicketEncryptor"/> class.
    /// </summary>
    /// <param name="decryptionKey">The decryption key.</param>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="compatibilityMode">The compatibility mode.</param>
    public LegacyFormsAuthenticationTicketEncryptor(string decryptionKey, string validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
    {
        var descriptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        var validationKeyBytes = HexUtils.HexToBinary(validationKey);

        Initialize(descriptionKeyBytes, validationKeyBytes, hashAlgorithm, compatibilityMode);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LegacyFormsAuthenticationTicketEncryptor"/> class.
    /// </summary>
    /// <param name="decryptionKey">The decryption key.</param>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="compatibilityMode">The compatibility mode.</param>
    public LegacyFormsAuthenticationTicketEncryptor(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
    {
        Initialize(decryptionKey, validationKey, hashAlgorithm, compatibilityMode);
    }

    /// <summary>
    /// Initializes the specified decryption key.
    /// </summary>
    /// <param name="decryptionKey">The decryption key.</param>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="compatibilityMode">The compatibility mode.</param>
    private void Initialize(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm, CompatibilityMode compatibilityMode)
    {
        _compatibilityMode = compatibilityMode;
        _decryptionKeyBlob = KeyDerivator.DeriveKey(decryptionKey, _compatibilityMode);

        _hasher = HashProvider.Create(KeyDerivator.DeriveKey(validationKey, _compatibilityMode), hashAlgorithm);
    }

    /// <summary>
    /// Decrypts the ticket
    /// </summary>
    /// <param name="cookieString">The cookie string.</param>
    /// <returns>FormsAuthenticationTicket.</returns>
    /// <exception cref="System.Exception">Invalid Hash</exception>
    public FormsAuthenticationTicket DecryptCookie(string cookieString)
    {
        byte[] cookieBlob = null!;

        if ((cookieString.Length % 2) == 0)
        {
            try
            {
                cookieBlob = HexUtils.HexToBinary(cookieString);
            }
            catch
            {
                // ignored
            }
        }

        if (cookieBlob == null)
            return null;

        var decryptedCookie = Decrypt(cookieBlob, _hasher, true);
        var ticketLength = decryptedCookie.Length;

        if (_compatibilityMode == CompatibilityMode.Framework20SP2)
        {
            ticketLength = decryptedCookie.Length - _hasher.HashSize;
            var validHash = _hasher.CheckHash(decryptedCookie, ticketLength);

            if (!validHash)
                throw new Exception("Invalid Hash");
        }

        return FormsAuthenticationTicketHelper.Deserialize(decryptedCookie, ticketLength);
    }

    /// <summary>
    /// Encrypts the cookie data.
    /// </summary>
    /// <param name="cookieBlob">The cookie BLOB.</param>
    /// <param name="hasher">The hasher.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="System.NotImplementedException"></exception>
    private byte[] EncryptCookieData(byte[] cookieBlob, HashProvider? hasher = null)
    {
        using (var aesProvider = Aes.Create())
        {
            aesProvider.Key = _decryptionKeyBlob;
            aesProvider.BlockSize = 128;
            aesProvider.GenerateIV();

            if (_compatibilityMode == CompatibilityMode.Framework20SP2)
            {
                aesProvider.IV = new byte[aesProvider.IV.Length];
                aesProvider.Mode = CipherMode.CBC;
            }
            else if (hasher != null)
                aesProvider.IV = hasher.GetIVHash(cookieBlob, aesProvider.IV.Length);

            var decryptor = aesProvider.CreateEncryptor();

            using (var ms = new MemoryStream())
            {
                if (_compatibilityMode != CompatibilityMode.Framework20SP2)
                    ms.Write(aesProvider.IV, 0, aesProvider.IV.Length);

                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    var sign = false;
                    if (_compatibilityMode == CompatibilityMode.Framework20SP2)
                    {
                        var createIv = true;
                        var useRandomIv = true;

                        if (createIv)
                        {
                            var ivLength = RoundupNumBitsToNumBytes(aesProvider.KeySize);
                            byte[] iv = null;

                            if (hasher != null)
                                iv = hasher.GetIVHash(cookieBlob, ivLength);
                            else if (useRandomIv)
                            {
                                iv = new byte[ivLength];
                                RandomNumberGenerator.GetBytes(iv);
                            }

                            cs.Write(iv, 0, iv.Length);
                        }
                    }

                    cs.Write(cookieBlob, 0, cookieBlob.Length);

                    cs.FlushFinalBlock();
                    var paddedData = ms.ToArray();

                    if (_compatibilityMode == CompatibilityMode.Framework20SP2 && sign)
                        throw new NotImplementedException();

                    return paddedData;
                }
            }
        }
    }

    /// <summary>
    /// Decrypts the specified cookie BLOB.
    /// </summary>
    /// <param name="cookieBlob">The cookie BLOB.</param>
    /// <param name="hasher">The hasher.</param>
    /// <param name="isHashAppended">if set to <c>true</c> [is hash appended].</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="System.ArgumentNullException">hasher</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Signature verification failed</exception>
    /// <exception cref="System.Exception">Unexpected salt length: {ivLength}. Total: {paddedData.Length}</exception>
    private byte[] Decrypt(byte[] cookieBlob, HashProvider hasher, bool isHashAppended)
    {
        if (hasher == null)
            throw new ArgumentNullException("hasher");

        if (isHashAppended)
        {
            cookieBlob = hasher.CheckHashAndRemove(cookieBlob);
            if (cookieBlob == null)
                throw new CryptographicException("Signature verification failed");
        }

        // Now decrypt the encrypted cookie data.
        using (var aesProvider = Aes.Create())
        {
            aesProvider.Key = _decryptionKeyBlob;
            aesProvider.BlockSize = 128;
            if (_compatibilityMode == CompatibilityMode.Framework20SP2)
            {
                aesProvider.GenerateIV();
                aesProvider.IV = new byte[aesProvider.IV.Length];
                aesProvider.Mode = CipherMode.CBC;
            }
            else
            {
                var iv = new byte[aesProvider.IV.Length];
                Buffer.BlockCopy(cookieBlob, 0, iv, 0, iv.Length);
                aesProvider.IV = iv;
            }

            using (var ms = new MemoryStream())
            {
                using (var decryptor = aesProvider.CreateDecryptor())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        if (_compatibilityMode == CompatibilityMode.Framework20SP2)
                            cs.Write(cookieBlob, 0, cookieBlob.Length);
                        else
                            cs.Write(cookieBlob, aesProvider.IV.Length, cookieBlob.Length - aesProvider.IV.Length);

                        cs.FlushFinalBlock();
                        var paddedData = ms.ToArray();

                        if (_compatibilityMode != CompatibilityMode.Framework20SP2)
                            return paddedData;

                        var ivLength = RoundupNumBitsToNumBytes(aesProvider.KeySize);
                        var dataLength = paddedData.Length - ivLength;
                        if (dataLength < 0)
                            throw new Exception($"Unexpected salt length: {ivLength}. Total: {paddedData.Length}");

                        var decryptedData = new byte[dataLength];
                        Buffer.BlockCopy(paddedData, ivLength, decryptedData, 0, dataLength);
                        return decryptedData;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Roundups the number bits to number bytes.
    /// </summary>
    /// <param name="numBits">The number bits.</param>
    /// <returns>System.Int32.</returns>
    internal static int RoundupNumBitsToNumBytes(int numBits)
    {
        if (numBits < 0)
            return 0;
        return (numBits / 8) + (((numBits & 7) != 0) ? 1 : 0);
    }

    /// <summary>
    /// Encrypts the ticket, and if a hasher is provided, will also include a signature in the encrypted data.
    /// </summary>
    /// <param name="ticket">The ticket.</param>
    /// <param name="randomiseUsingHash">If true, the hash of the encrypted data will be prepended to the beginning, otherwise random bytes will be generated and prepended to the beggining.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.Exception">Invalid ticket</exception>
    /// <exception cref="System.Exception">Unable to get HMACSHAHash</exception>
    /// <exception cref="System.Exception">Unable to encrypt cookie</exception>
    /// <exception cref="System.Exception">Unable to sign cookie</exception>
    public string Encrypt(FormsAuthenticationTicket ticket, bool randomiseUsingHash = false)
    {
        var ticketBlob = FormsAuthenticationTicketHelper.Serialize(ticket);
        if (ticketBlob == null)
            throw new Exception("Invalid ticket");

        var cookieBlob = ticketBlob;

        if (_compatibilityMode == CompatibilityMode.Framework20SP2 && _hasher != null)
        {
            var hashBlob = _hasher.GetHMACSHAHash(ticketBlob, null, 0, ticketBlob.Length);
            if (hashBlob == null)
                throw new Exception("Unable to get HMACSHAHash");

            cookieBlob = new byte[hashBlob.Length + ticketBlob.Length];
            Buffer.BlockCopy(ticketBlob, 0, cookieBlob, 0, ticketBlob.Length);
            Buffer.BlockCopy(hashBlob, 0, cookieBlob, ticketBlob.Length, hashBlob.Length);
        }

        var encryptedCookieBlob = EncryptCookieData(cookieBlob, randomiseUsingHash ? _hasher : null);

        if (encryptedCookieBlob == null)
            throw new Exception("Unable to encrypt cookie");

        if (_hasher != null)
        {
            var hashBlob = _hasher.GetHMACSHAHash(encryptedCookieBlob, null, 0, encryptedCookieBlob.Length);
            if (hashBlob == null)
                throw new Exception("Unable to sign cookie");

            cookieBlob = new byte[hashBlob.Length + encryptedCookieBlob.Length];
            Buffer.BlockCopy(encryptedCookieBlob, 0, cookieBlob, 0, encryptedCookieBlob.Length);
            Buffer.BlockCopy(hashBlob, 0, cookieBlob, encryptedCookieBlob.Length, hashBlob.Length);
        }

        return HexUtils.BinaryToHex(cookieBlob);
    }
}
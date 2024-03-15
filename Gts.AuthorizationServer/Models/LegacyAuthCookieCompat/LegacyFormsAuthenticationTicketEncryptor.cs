using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

public class LegacyFormsAuthenticationTicketEncryptor
{
    private const ShaVersion DefaultHashAlgorithm = ShaVersion.Sha1;

    private const CompatibilityMode DefaultCompatibilityMode = CompatibilityMode.Framework20SP2;

    private static RandomNumberGenerator _randomNumberGenerator;

    private byte[] _decryptionKeyBlob;

    private CompatibilityMode _compatibilityMode;

    private HashProvider _hasher;

    private static RandomNumberGenerator RandomNumberGenerator
    {
        get
        {
            if (_randomNumberGenerator == null)
                _randomNumberGenerator = RandomNumberGenerator.Create();

            return _randomNumberGenerator;
        }
    }

    public LegacyFormsAuthenticationTicketEncryptor(string decryptionKey, string validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
    {
        var descriptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        var validationKeyBytes = HexUtils.HexToBinary(validationKey);

        Initialize(descriptionKeyBytes, validationKeyBytes, hashAlgorithm, compatibilityMode);
    }

    public LegacyFormsAuthenticationTicketEncryptor(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
    {
        Initialize(decryptionKey, validationKey, hashAlgorithm, compatibilityMode);
    }

    private void Initialize(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm, CompatibilityMode compatibilityMode)
    {
        _compatibilityMode = compatibilityMode;
        _decryptionKeyBlob = KeyDerivator.DeriveKey(decryptionKey, _compatibilityMode);

        _hasher = HashProvider.Create(KeyDerivator.DeriveKey(validationKey, _compatibilityMode), hashAlgorithm);
    }

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

    internal static int RoundupNumBitsToNumBytes(int numBits)
    {
        if (numBits < 0)
            return 0;
        return (numBits / 8) + (((numBits & 7) != 0) ? 1 : 0);
    }

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
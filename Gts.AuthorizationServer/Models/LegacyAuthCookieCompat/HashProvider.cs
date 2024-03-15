using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

public abstract class HashProvider
{
    private static int _hashSize;

    private static int _keySize;

    private byte[] _validationKeyBlob;

    private byte[] _inner = null;

    private byte[] _outer = null;

    public static HashProvider Create(byte[] validationKey, ShaVersion hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
            case ShaVersion.Sha1:
                return new Sha1HashProvider(validationKey);
            case ShaVersion.Sha256:
                return new Sha256HashProvider(validationKey);
            case ShaVersion.Sha384:
                return new Sha384HashProvider(validationKey);
            case ShaVersion.Sha512:
                return new Sha512HashProvider(validationKey);
            default:
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
        }
    }

    protected HashProvider(byte[] validationKey, int hashSize, int keySize)
    {
        _hashSize = hashSize;
        _keySize = keySize;
        _validationKeyBlob = validationKey;
        SetInnerOuterKeys(_validationKeyBlob, ref _inner, ref _outer);
    }

    protected abstract HMAC CreateHasher(byte[] key);

    public byte[] GetHMACSHAHash(byte[] buf, byte[] modifier, int start, int length)
    {
        if (start < 0 || start > buf.Length)
            throw new ArgumentException("start");
        if (length < 0 || buf == null || (start + length) > buf.Length)
            throw new ArgumentException("length");

        var hasher = CreateHasher(_validationKeyBlob);

        var hash = hasher.ComputeHash(buf, start, length);

        return hash;
    }

    public byte[] CheckHashAndRemove(byte[] bufHashed)
    {
        if (!CheckHash(bufHashed, bufHashed.Length - _hashSize))
            return null;

        var buf2 = new byte[bufHashed.Length - _hashSize];
        Buffer.BlockCopy(bufHashed, 0, buf2, 0, buf2.Length);
        return buf2;
    }

    public bool CheckHash(byte[] decryptedCookie, int hashIndex)
    {
        var hashCheckBlob = GetHMACSHAHash(decryptedCookie, null, 0, hashIndex);
        if (hashCheckBlob == null)
            throw new Exception("Hash is not appended to the end.");

        if (hashCheckBlob == null || hashCheckBlob.Length != _hashSize)
            throw new Exception($"Invalid hash length: {hashCheckBlob.Length}, expected {_hashSize}");
        
        var hashCheckFailed = false;
        for (var i = 0; i < _hashSize; i++)
        {
            if (hashCheckBlob[i] != decryptedCookie[hashIndex + i])
                hashCheckFailed = true;
        }

        return !hashCheckFailed;
    }

    private void SetInnerOuterKeys(byte[] validationKey, ref byte[] inner, ref byte[] outer)
    {
        byte[] key = null;
        if (validationKey.Length > _keySize)
        {
            key = new byte[_hashSize];

            var hmacsha1Hasher = CreateHasher(validationKey);
            hmacsha1Hasher.ComputeHash(key);
        }

        if (inner == null)
            inner = new byte[_keySize];
        if (outer == null)
            outer = new byte[_keySize];

        int i;
        for (i = 0; i < _keySize; i++)
        {
            inner[i] = 0x36;
            outer[i] = 0x5C;
        }
        for (i = 0; i < validationKey.Length; i++)
        {
            inner[i] ^= validationKey[i];
            outer[i] ^= validationKey[i];
        }
    }

    public int HashSize { get { return _hashSize; } }

    public byte[] GetIVHash(byte[] buf, int ivLength)
    {
        var bytesToWrite = ivLength;
        var bytesWritten = 0;
        var iv = new byte[ivLength];

        var hash = buf;
        while (bytesWritten < ivLength)
        {
            var newHash = new byte[_hashSize];

            var hmacsha1Hasher = CreateHasher(_validationKeyBlob);
            newHash = hmacsha1Hasher.ComputeHash(hash);

            var bytesToCopy = Math.Min(_hashSize, bytesToWrite);
            Buffer.BlockCopy(hash, 0, iv, bytesWritten, bytesToCopy);

            bytesWritten += bytesToCopy;
            bytesToWrite -= bytesToCopy;
        }
        return iv;
    }
}
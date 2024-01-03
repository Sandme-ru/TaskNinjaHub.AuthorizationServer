using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class HashProvider.
/// </summary>
public abstract class HashProvider
{
    /// <summary>
    /// The hash size
    /// </summary>
    private static int _hashSize;

    /// <summary>
    /// The key size
    /// </summary>
    private static int _keySize;

    /// <summary>
    /// The validation key BLOB
    /// </summary>
    private byte[] _validationKeyBlob;

    /// <summary>
    /// The inner
    /// </summary>
    private byte[] _inner = null;

    /// <summary>
    /// The outer
    /// </summary>
    private byte[] _outer = null;

    /// <summary>
    /// Creates the specified validation key.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>HashProvider.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">hashAlgorithm</exception>
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

    /// <summary>
    /// Initializes a new instance of the <see cref="HashProvider"/> class.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="hashSize">Size of the hash.</param>
    /// <param name="keySize">Size of the key.</param>
    protected HashProvider(byte[] validationKey, int hashSize, int keySize)
    {
        _hashSize = hashSize;
        _keySize = keySize;
        _validationKeyBlob = validationKey;
        SetInnerOuterKeys(_validationKeyBlob, ref _inner, ref _outer);
    }

    /// <summary>
    /// Creates the hasher.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <returns>HMAC.</returns>
    protected abstract HMAC CreateHasher(byte[] key);

    /// <summary>
    /// Gets the hmacsha hash.
    /// </summary>
    /// <param name="buf">The buf.</param>
    /// <param name="modifier">The modifier.</param>
    /// <param name="start">The start.</param>
    /// <param name="length">The length.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="System.ArgumentException">start</exception>
    /// <exception cref="System.ArgumentException">length</exception>
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

    /// <summary>
    /// Checks the hash and remove.
    /// </summary>
    /// <param name="bufHashed">The buf hashed.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] CheckHashAndRemove(byte[] bufHashed)
    {
        if (!CheckHash(bufHashed, bufHashed.Length - _hashSize))
            return null;

        var buf2 = new byte[bufHashed.Length - _hashSize];
        Buffer.BlockCopy(bufHashed, 0, buf2, 0, buf2.Length);
        return buf2;
    }

    /// <summary>
    /// Checks the hash.
    /// </summary>
    /// <param name="decryptedCookie">The decrypted cookie.</param>
    /// <param name="hashIndex">Index of the hash.</param>
    /// <returns><c>true</c> if XXXX, <c>false</c> otherwise.</returns>
    /// <exception cref="System.Exception">Hash is not appended to the end.</exception>
    /// <exception cref="System.Exception">Invalid hash length: {hashCheckBlob.Length}, expected {_hashSize}</exception>
    public bool CheckHash(byte[] decryptedCookie, int hashIndex)
    {
        // 2. SHA1 Hash is appended to the end.
        // Verify the hash matches by re-computing the hash for this message, and comparing.
        var hashCheckBlob = GetHMACSHAHash(decryptedCookie, null, 0, hashIndex);
        if (hashCheckBlob == null)
            throw new Exception("Hash is not appended to the end.");

        //////////////////////////////////////////////////////////////////////
        // Step 2: Make sure the MAC has expected length
        if (hashCheckBlob == null || hashCheckBlob.Length != _hashSize)
            throw new Exception($"Invalid hash length: {hashCheckBlob.Length}, expected {_hashSize}");


        // To prevent a timing attack, we should verify the entire hash instead of failing
        // early the first time we see a mismatched byte.            
        var hashCheckFailed = false;
        for (var i = 0; i < _hashSize; i++)
        {
            if (hashCheckBlob[i] != decryptedCookie[hashIndex + i])
                hashCheckFailed = true;
        }

        return !hashCheckFailed;
    }

    /// <summary>
    /// Sets the inner outer keys.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    /// <param name="inner">The inner.</param>
    /// <param name="outer">The outer.</param>
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

    /// <summary>
    /// Gets the size of the hash.
    /// </summary>
    /// <value>The size of the hash.</value>
    public int HashSize { get { return _hashSize; } }

    /// <summary>
    /// Gets the iv hash.
    /// </summary>
    /// <param name="buf">The buf.</param>
    /// <param name="ivLength">Length of the iv.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] GetIVHash(byte[] buf, int ivLength)
    {
        // return an IV that is computed as a hash of the buffer
        var bytesToWrite = ivLength;
        var bytesWritten = 0;
        var iv = new byte[ivLength];

        // get SHA1 hash of the buffer and copy to the IV.
        // if hash length is less than IV length, re-hash the hash and
        // append until IV is full.
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
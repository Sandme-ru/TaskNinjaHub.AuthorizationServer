using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class Sha512HashProvider.
/// Implements the <see cref="HashProvider" />
/// </summary>
/// <seealso cref="HashProvider" />
class Sha512HashProvider : HashProvider
{
    /// <summary>
    /// The sha1 hash size
    /// </summary>
    const int Sha1HashSize = 64;

    /// <summary>
    /// The sha1 key size
    /// </summary>
    const int Sha1KeySize = 512;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha512HashProvider"/> class.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    public Sha512HashProvider(byte[] validationKey) : base(validationKey, Sha1HashSize, Sha1KeySize)
    {
    }

    /// <summary>
    /// Creates the hasher.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <returns>HMAC.</returns>
    protected override HMAC CreateHasher(byte[] key) => new HMACSHA512(key);
}
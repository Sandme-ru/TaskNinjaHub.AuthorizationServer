using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class Sha1HashProvider.
/// Implements the <see cref="HashProvider" />
/// </summary>
/// <seealso cref="HashProvider" />
public class Sha1HashProvider : HashProvider
{
    /// <summary>
    /// The sha1 hash size
    /// </summary>
    const int Sha1HashSize = 20;

    /// <summary>
    /// The sha1 key size
    /// </summary>
    const int Sha1KeySize = 64;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha1HashProvider"/> class.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    public Sha1HashProvider(byte[] validationKey) : base(validationKey, Sha1HashSize, Sha1KeySize)
    {
    }

    /// <summary>
    /// Creates the hasher.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <returns>HMAC.</returns>
    protected override HMAC CreateHasher(byte[] key) => new HMACSHA1(key);
}
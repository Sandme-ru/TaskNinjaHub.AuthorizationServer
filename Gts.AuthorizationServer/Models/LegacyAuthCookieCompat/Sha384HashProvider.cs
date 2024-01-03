using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class Sha384HashProvider.
/// Implements the <see cref="HashProvider" />
/// </summary>
/// <seealso cref="HashProvider" />
internal class Sha384HashProvider : HashProvider
{
    /// <summary>
    /// The sha384 hash size
    /// </summary>
    private const int Sha384HashSize = 48;

    /// <summary>
    /// The sha384 key size
    /// </summary>
    private const int Sha384KeySize = 384;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha384HashProvider"/> class.
    /// </summary>
    /// <param name="validationKey">The validation key.</param>
    public Sha384HashProvider(byte[] validationKey) : base(validationKey, Sha384HashSize, Sha384KeySize)
    {
    }

    /// <summary>
    /// Creates the hasher.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <returns>HMAC.</returns>
    protected override HMAC CreateHasher(byte[] key) => new HMACSHA384(key);
}
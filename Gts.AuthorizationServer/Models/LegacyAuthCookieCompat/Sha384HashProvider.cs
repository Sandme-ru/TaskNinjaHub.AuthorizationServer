using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

internal class Sha384HashProvider(byte[] validationKey) : HashProvider(validationKey, Sha384HashSize, Sha384KeySize)
{
    private const int Sha384HashSize = 48;

    private const int Sha384KeySize = 384;

    protected override HMAC CreateHasher(byte[] key) => new HMACSHA384(key);
}
using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

class Sha256HashProvider(byte[] validationKey) : HashProvider(validationKey, Sha1HashSize, Sha1KeySize)
{
    const int Sha1HashSize = 32;

    const int Sha1KeySize = 256;

    protected override HMAC CreateHasher(byte[] key) => new HMACSHA256(key);
}
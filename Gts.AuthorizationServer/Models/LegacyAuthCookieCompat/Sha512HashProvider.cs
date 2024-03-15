using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

class Sha512HashProvider(byte[] validationKey) : HashProvider(validationKey, Sha1HashSize, Sha1KeySize)
{
    const int Sha1HashSize = 64;

    const int Sha1KeySize = 512;

    protected override HMAC CreateHasher(byte[] key) => new HMACSHA512(key);
}
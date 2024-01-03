namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class HexUtils.
/// </summary>
public static class HexUtils
{
    /// <summary>
    /// Converts a byte array into it's string representation.
    /// </summary>
    /// <param name="data">byte array</param>
    /// <returns>The byte array corresponding to the contents of the hex string,
    /// or null if the input string is not a valid hex string.</returns>
    public static string BinaryToHex(byte[] data)
    {
        if (data == null)
            return null!;

        var hex = new char[checked(data.Length * 2)];

        for (var i = 0; i < data.Length; i++)
        {
            var thisByte = data[i];
            hex[2 * i] = NibbleToHex((byte)(thisByte >> 4)); // high nibble
            hex[2 * i + 1] = NibbleToHex((byte)(thisByte & 0xf)); // low nibble
        }

        return new string(hex);
    }

    /// <summary>
    /// Converts a hexadecimal string into it's binary representation.
    /// </summary>
    /// <param name="data">The hex string.</param>
    /// <returns>The byte array corresponding to the contents of the hex string,
    /// or null if the input string is not a valid hex string.</returns>
    public static byte[] HexToBinary(string data)
    {
        if (data == null || data.Length % 2 != 0)
            return null!;

        var binary = new byte[data.Length / 2];

        for (var i = 0; i < binary.Length; i++)
        {
            var highNibble = HexToInt(data[2 * i]);
            var lowNibble = HexToInt(data[2 * i + 1]);

            if (highNibble == -1 || lowNibble == -1)
                return null!;

            binary[i] = (byte)((highNibble << 4) | lowNibble);
        }

        return binary;
    }

    /// <summary>
    /// Hexadecimals to int.
    /// </summary>
    /// <param name="h">The h.</param>
    /// <returns>System.Int32.</returns>
    public static int HexToInt(char h)
    {
        return (h >= '0' && h <= '9') ? h - '0' :
            (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
            (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
            -1;
    }

    /// <summary>
    /// Nibbles to hexadecimal.
    /// </summary>
    /// <param name="nibble">The nibble.</param>
    /// <returns>System.Char.</returns>
    private static char NibbleToHex(byte nibble)
    {
        return (char)((nibble < 10) ? (nibble + '0') : (nibble - 10 + 'A'));
    }
}
using System.Diagnostics;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

internal static class FormsAuthenticationTicketHelper
{
    private const byte CURRENT_TICKET_SERIALIZED_VERSION = 0x01;

    private const int MAX_TICKET_LENGTH = 4096;

    public static FormsAuthenticationTicket Deserialize(byte[] serializedTicket, int serializedTicketLength)
    {
        try
        {
            using (var ticketBlobStream = new MemoryStream(serializedTicket))
            {
                using (var ticketReader = new SerializingBinaryReader(ticketBlobStream))
                {

                    // Step 1: Read the serialized format version number from the stream.
                    // Currently the only supported format is 0x01.
                    // LENGTH: 1 byte
                    byte serializedFormatVersion = ticketReader.ReadByte();
                    if (serializedFormatVersion != CURRENT_TICKET_SERIALIZED_VERSION)
                    {
                        return null; // unexpected value
                    }

                    // Step 2: Read the ticket version number from the stream.
                    // LENGTH: 1 byte
                    int ticketVersion = ticketReader.ReadByte();

                    // Step 3: Read the ticket issue date from the stream.
                    // LENGTH: 8 bytes
                    var ticketIssueDateUtcTicks = ticketReader.ReadInt64();
                    var ticketIssueDateUtc = new DateTime(ticketIssueDateUtcTicks, DateTimeKind.Utc);
                    var ticketIssueDateLocal = ticketIssueDateUtc.ToLocalTime();

                    // Step 4: Read the spacer from the stream.
                    // LENGTH: 1 byte
                    var spacer = ticketReader.ReadByte();
                    if (spacer != 0xfe)
                    {
                        return null; // unexpected value
                    }

                    // Step 5: Read the ticket expiration date from the stream.
                    // LENGTH: 8 bytes
                    var ticketExpirationDateUtcTicks = ticketReader.ReadInt64();
                    var ticketExpirationDateUtc = new DateTime(ticketExpirationDateUtcTicks, DateTimeKind.Utc);
                    var ticketExpirationDateLocal = ticketExpirationDateUtc.ToLocalTime();

                    // Step 6: Read the ticket persistence field from the stream.
                    // LENGTH: 1 byte
                    var ticketPersistenceFieldValue = ticketReader.ReadByte();
                    bool ticketIsPersistent;
                    switch (ticketPersistenceFieldValue)
                    {
                        case 0:
                            ticketIsPersistent = false;
                            break;
                        case 1:
                            ticketIsPersistent = true;
                            break;
                        default:
                            return null; // unexpected value
                    }

                    // Step 7: Read the ticket username from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    var ticketName = ticketReader.ReadBinaryString();

                    // Step 8: Read the ticket custom data from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    var ticketUserData = ticketReader.ReadBinaryString();

                    // Step 9: Read the ticket cookie path from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    var ticketCookiePath = ticketReader.ReadBinaryString();

                    // Step 10: Read the footer from the stream.
                    // LENGTH: 1 byte
                    var footer = ticketReader.ReadByte();
                    if (footer != 0xff)
                    {
                        return null; // unexpected value
                    }

                    // Step 11: Verify that we have consumed the entire payload.
                    // We don't expect there to be any more information after the footer.
                    // The caller is responsible for telling us when the actual payload
                    // is finished, as he may have handed us a byte array that contains
                    // the payload plus signature as an optimization, and we don't want
                    // to misinterpet the signature as a continuation of the payload.
                    if (ticketBlobStream.Position != serializedTicketLength)
                    {
                        return null;
                    }

                    // Success.
                    return FromUtc(
                        ticketVersion /* version */,
                        ticketName /* name */,
                        ticketIssueDateUtc /* issueDateUtc */,
                        ticketExpirationDateUtc /* expirationUtc */,
                        ticketIsPersistent /* isPersistent */,
                        ticketUserData /* userData */,
                        ticketCookiePath /* cookiePath */);
                }
            }
        }
        catch
        {
            // If anything goes wrong while parsing the token, just treat the token as invalid.
            return null;
        }
    }

    internal static FormsAuthenticationTicket FromUtc(int version, string name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, string userData, string cookiePath)
    {
        var ticket = new FormsAuthenticationTicket(version, name, issueDateUtc.ToLocalTime(), expirationUtc.ToLocalTime(), isPersistent, userData, cookiePath);
        return ticket;
    }

    public static byte[] Serialize(FormsAuthenticationTicket ticket)
    {
        using (var ticketBlobStream = new MemoryStream())
        {
            using (var ticketWriter = new SerializingBinaryWriter(ticketBlobStream))
            {
                ticketWriter.Write(CURRENT_TICKET_SERIALIZED_VERSION);
                ticketWriter.Write((byte)ticket.Version);
                ticketWriter.Write(ticket.IssueDate.ToUniversalTime().Ticks);
                Debug.Assert(ticketBlobStream.Position == 10, "Critical that we be at position 10 in the stream at this point.");
                ticketWriter.Write((byte)0xfe);
                ticketWriter.Write(ticket.Expiration.ToUniversalTime().Ticks);
                ticketWriter.Write(ticket.IsPersistent);
                ticketWriter.WriteBinaryString(ticket.Name);
                ticketWriter.WriteBinaryString(ticket.UserData);
                ticketWriter.WriteBinaryString(ticket.CookiePath);
                ticketWriter.Write((byte)0xff);
                return ticketBlobStream.ToArray();
            }
        }
    }

    private sealed class SerializingBinaryReader(Stream input) : BinaryReader(input)
    {
        public string ReadBinaryString()
        {
            var charCount = Read7BitEncodedInt();
            var bytes = ReadBytes(charCount * 2);

            var chars = new char[charCount];
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
            }

            return new string(chars);
        }

        public override string ReadString()
        {
            throw new NotImplementedException();
        }
    }

    private sealed class SerializingBinaryWriter(Stream output) : BinaryWriter(output)
    {
        public override void Write(string value)
        {
            throw new NotImplementedException();
        }

        public void WriteBinaryString(string value)
        {
            var bytes = new byte[value.Length * 2];
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                bytes[2 * i] = (byte)c;
                bytes[2 * i + 1] = (byte)(c >> 8);
            }

            Write7BitEncodedInt(value.Length);
            Write(bytes);
        }
    }

}
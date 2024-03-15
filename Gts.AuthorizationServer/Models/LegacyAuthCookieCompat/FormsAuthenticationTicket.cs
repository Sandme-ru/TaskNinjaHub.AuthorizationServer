namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

public sealed class FormsAuthenticationTicket(
    int version,
    string name,
    DateTime issueDate,
    DateTime expiration,
    bool isPersistent,
    string userData,
    string cookiePath)
{
    public int Version { get; private set; } = version;

    public string Name { get; private set; } = name;

    public DateTime IssueDate { get; private set; } = issueDate;

    public DateTime Expiration { get; private set; } = expiration;

    public bool IsPersistent { get; private set; } = isPersistent;

    public string UserData { get; private set; } = userData;

    public string CookiePath { get; private set; } = cookiePath;

    public bool Expired => DateTime.Now > Expiration;
}
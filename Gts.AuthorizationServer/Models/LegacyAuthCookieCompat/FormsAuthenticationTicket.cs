namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class FormsAuthenticationTicket. This class cannot be inherited.
/// </summary>
public sealed class FormsAuthenticationTicket
{
    /// <summary>
    /// Gets the version.
    /// </summary>
    /// <value>The version.</value>
    public int Version { get; private set; }

    /// <summary>
    /// Gets the name.
    /// </summary>
    /// <value>The name.</value>
    public string Name { get; private set; }

    /// <summary>
    /// Gets the issue date.
    /// </summary>
    /// <value>The issue date.</value>
    public DateTime IssueDate { get; private set; }

    /// <summary>
    /// Gets the expiration.
    /// </summary>
    /// <value>The expiration.</value>
    public DateTime Expiration { get; private set; }

    /// <summary>
    /// Gets a value indicating whether this instance is persistent.
    /// </summary>
    /// <value><c>true</c> if this instance is persistent; otherwise, <c>false</c>.</value>
    public bool IsPersistent { get; private set; }

    /// <summary>
    /// Gets the user data.
    /// </summary>
    /// <value>The user data.</value>
    public string UserData { get; private set; }

    /// <summary>
    /// Gets the cookie path.
    /// </summary>
    /// <value>The cookie path.</value>
    public string CookiePath { get; private set; }

    /// <summary>
    /// Gets a value indicating whether this <see cref="FormsAuthenticationTicket"/> is expired.
    /// </summary>
    /// <value><c>true</c> if expired; otherwise, <c>false</c>.</value>
    public bool Expired => DateTime.Now > Expiration;

    /// <summary>
    /// Initializes a new instance of the <see cref="FormsAuthenticationTicket"/> class.
    /// </summary>
    /// <param name="version">The version.</param>
    /// <param name="name">The name.</param>
    /// <param name="issueDate">The issue date.</param>
    /// <param name="expiration">The expiration.</param>
    /// <param name="isPersistent">if set to <c>true</c> [is persistent].</param>
    /// <param name="userData">The user data.</param>
    /// <param name="cookiePath">The cookie path.</param>
    public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData, string cookiePath)
    {
        Version = version;
        Name = name;
        IssueDate = issueDate;
        Expiration = expiration;
        IsPersistent = isPersistent;
        UserData = userData;
        CookiePath = cookiePath;
    }
}
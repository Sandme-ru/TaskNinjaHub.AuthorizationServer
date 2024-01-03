using System.ComponentModel;
using Microsoft.AspNetCore.Identity;

namespace Gts.AuthorizationServer.Models.Users;

/// <summary>
/// Class ApplicationUser.
/// Implements the <see cref="Microsoft.AspNetCore.Identity.IdentityUser{System.Guid}" />
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Identity.IdentityUser{System.Guid}" />
public class ApplicationUser : IdentityUser<Guid>
{
    /// <summary>
    /// Gets or sets the first name.
    /// </summary>
    /// <value>The first name.</value>
    public string? FirstName { get; set; }

    /// <summary>
    /// Gets or sets the last name.
    /// </summary>
    /// <value>The last name.</value>
    public string? LastName { get; set; }

    /// <summary>
    /// Gets or sets the name of the middle.
    /// </summary>
    /// <value>The name of the middle.</value>
    public string? MiddleName { get; set; }

    /// <summary>
    /// Gets the short name.
    /// </summary>
    /// <value>The short name.</value>
    public string ShortName => LastName + (string.IsNullOrWhiteSpace(FirstName) ? "" : " " + FirstName[0] + "." + (string.IsNullOrWhiteSpace(MiddleName) ? "" : MiddleName[0] + "."));

    /// <summary>
    /// Gets or sets a value indicating whether this instance is active.
    /// </summary>
    /// <value><c>true</c> if this instance is active; otherwise, <c>false</c>.</value>
    [DefaultValue(true)]
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Gets or sets the create date.
    /// </summary>
    /// <value>The create date.</value>
    [PersonalData]
    public DateTimeOffset CreateDate { get; set; }

    /// <summary>
    /// Gets or sets the last login date.
    /// </summary>
    /// <value>The last login date.</value>
    [PersonalData]
    public DateTimeOffset LastLoginDate { get; set; }
}
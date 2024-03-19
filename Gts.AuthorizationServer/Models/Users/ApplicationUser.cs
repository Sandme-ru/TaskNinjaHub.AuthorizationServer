using System.ComponentModel;
using Gts.AuthorizationServer.Models.Localization;
using Microsoft.AspNetCore.Identity;

namespace Gts.AuthorizationServer.Models.Users;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public string? MiddleName { get; set; }

    public string ShortName => LastName + (string.IsNullOrWhiteSpace(FirstName) ? "" : " " + FirstName[0] + "." + (string.IsNullOrWhiteSpace(MiddleName) ? "" : MiddleName[0] + "."));

    [DefaultValue(true)]
    public bool IsActive { get; set; } = true;

    [PersonalData]
    public DateTimeOffset CreateDate { get; set; }

    [PersonalData]
    public DateTimeOffset LastLoginDate { get; set; }

    public LocalizationType LocalizationType { get; set; }
}
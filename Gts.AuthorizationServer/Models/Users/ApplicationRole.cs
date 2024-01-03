using Microsoft.AspNetCore.Identity;

namespace Gts.AuthorizationServer.Models.Users;

/// <summary>
/// Class ApplicationRole.
/// Implements the <see cref="Microsoft.AspNetCore.Identity.IdentityRole{System.Guid}" />
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Identity.IdentityRole{System.Guid}" />
public class ApplicationRole : IdentityRole<Guid>
{

}

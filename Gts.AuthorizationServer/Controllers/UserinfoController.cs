using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Gts.AuthorizationServer.Controllers;

public class UserinfoController(UserManager<ApplicationUser> userManager, ILogger<UserinfoController> logger) : Controller
{
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        logger.LogInformation($"This is GetMessage method of UserinfoController");
        var user = await userManager.FindByIdAsync(User.GetClaim(OpenIddictConstants.Claims.Subject));
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Subject] = await userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = await userManager.GetEmailAsync(user);
            claims[OpenIddictConstants.Claims.EmailVerified] = await userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = await userManager.GetPhoneNumberAsync(user);
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = await userManager.IsPhoneNumberConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
            claims[OpenIddictConstants.Claims.Role] = await userManager.GetRolesAsync(user);

        return Ok(claims);
    }
}

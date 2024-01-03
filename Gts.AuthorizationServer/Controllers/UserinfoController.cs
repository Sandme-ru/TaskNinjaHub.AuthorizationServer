using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Gts.AuthorizationServer.Controllers;

/// <summary>
/// Class UserinfoController.
/// Implements the <see cref="Controller" />
/// </summary>
/// <seealso cref="Controller" />
public class UserinfoController : Controller
{
    /// <summary>
    /// The user manager
    /// </summary>
    private readonly UserManager<ApplicationUser> _userManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserinfoController"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    public UserinfoController(UserManager<ApplicationUser> userManager, ILogger<UserinfoController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    private readonly ILogger<UserinfoController> _logger;

    /// <summary>
    /// Userinfoes this instance.
    /// </summary>
    /// <returns>IActionResult.</returns>
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        _logger.LogInformation($"This is GetMessage method of UserinfoController");
        var user = await _userManager.FindByIdAsync(User.GetClaim(OpenIddictConstants.Claims.Subject));
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
            [OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = await _userManager.GetEmailAsync(user);
            claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = await _userManager.GetPhoneNumberAsync(user);
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = await _userManager.IsPhoneNumberConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
            claims[OpenIddictConstants.Claims.Role] = await _userManager.GetRolesAsync(user);

        return Ok(claims);
    }
}

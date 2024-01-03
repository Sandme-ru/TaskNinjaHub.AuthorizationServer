using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace Gts.AuthorizationServer.Controllers;

/// <summary>
/// Class ResourceController.
/// Implements the <see cref="Controller" />
/// </summary>
/// <seealso cref="Controller" />
[Route("api")]
public class ResourceController : Controller
{
    /// <summary>
    /// The user manager
    /// </summary>
    private readonly UserManager<ApplicationUser> _userManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="ResourceController"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    public ResourceController(UserManager<ApplicationUser> userManager, ILogger<ResourceController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    private readonly ILogger<ResourceController> _logger;

    /// <summary>
    /// Gets the message.
    /// </summary>
    /// <returns>IActionResult.</returns>
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("message")]
    public async Task<IActionResult> GetMessage()
    {
        _logger.LogInformation($"This is GetMessage method of ResourceController");
        var user = await _userManager.FindByIdAsync(User.GetClaim(OpenIddictConstants.Claims.Subject));
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictValidationAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                    [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        return Content($"{user.UserName} has been successfully authenticated.");
    }
}

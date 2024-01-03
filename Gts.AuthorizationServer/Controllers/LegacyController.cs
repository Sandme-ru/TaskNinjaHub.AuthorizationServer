using Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

/// <summary>
/// Class LegacyController.
/// Implements the <see cref="Controller" />
/// </summary>
/// <seealso cref="Controller" />
public class LegacyController : Controller
{
    /// <summary>
    /// The sign in manager
    /// </summary>
    private readonly SignInManager<ApplicationUser> _signInManager;

    /// <summary>
    /// The user manager
    /// </summary>
    private readonly UserManager<ApplicationUser> _userManager;

    private readonly ILogger<LegacyController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="LegacyController"/> class.
    /// </summary>
    /// <param name="signInManager">The sign in manager.</param>
    /// <param name="userManager">The user manager.</param>
    public LegacyController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LegacyController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Logins the specified return URL.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>IActionResult.</returns>
    public async Task<IActionResult> Login(string returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        Request.Cookies.TryGetValue(LegacyAuthCookieCompatDefaults.CookieUserName, out var userNameCookie);

        if (userNameCookie != null)
        {
            var validationKey = LegacyAuthCookieCompatDefaults.ValidationKey;
            var decryptionKey = LegacyAuthCookieCompatDefaults.DecryptionKey;

            var decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
            var validationKeyBytes = HexUtils.HexToBinary(validationKey);

            var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);

            var decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(userNameCookie);
            if (decryptedTicket != null)
            {
                var userName = decryptedTicket?.UserData;

                var user = await _userManager.Users.FirstOrDefaultAsync(f => (f.LastName + " " + f.FirstName + " " + f.MiddleName == userName) || f.UserName == userName);
                if (user != null)
                {
                    await _signInManager.SignInAsync(user, false);
                    _logger.LogInformation($"User loggining {userName}");
                    return LocalRedirect(returnUrl);
                }
            }
        }

        return Challenge(
            authenticationSchemes: IdentityConstants.ApplicationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = returnUrl
            });
    }
}
using Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

public class LegacyController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    ILogger<LegacyController> logger)
    : Controller
{
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

                var user = await userManager.Users.FirstOrDefaultAsync(f => (f.LastName + " " + f.FirstName + " " + f.MiddleName == userName) || f.UserName == userName);
                if (user != null)
                {
                    await signInManager.SignInAsync(user, false);
                    logger.LogInformation($"User loggining {userName}");
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
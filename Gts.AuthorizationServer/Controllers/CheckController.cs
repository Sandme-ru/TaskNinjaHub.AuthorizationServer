using Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

public class CheckController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    ILogger<CheckController> logger)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        Request.Cookies.TryGetValue(".ASPXAUTH_EDISON_USERNAME", out var userNameCookie);

        if(userNameCookie == null)
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties { RedirectUri = "/" });

        var validationKey = "191B33B15DBAB35174DA0284D5D4A4657AA35049C6B9991FDE4523EB0E5F488A6DF605333EBB1C5FAC1F5D4B98C37E0C401D40946E3882F0BA85183BBFDC2926";
        var decryptionKey = "44656019D1C499B6CF7D418F844DA551BBC977D67ED994AA6139DF256BE981E6";

        var decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        var validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);

        var decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(userNameCookie);

        var userName = decryptedTicket.UserData;

        var user = await userManager.Users.FirstOrDefaultAsync(f => f.LastName + " " + f.FirstName + " " + f.MiddleName == userName);
        if (user == null)
        {
            logger.LogWarning("Not found user {UserName}", userName);
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties { RedirectUri = "/" });
        }

        logger.LogInformation("User logged in {UserName}", userName);

        await signInManager.SignInAsync(user, isPersistent: false);

        return Json(new { userNameCookie, userName });
    }
}
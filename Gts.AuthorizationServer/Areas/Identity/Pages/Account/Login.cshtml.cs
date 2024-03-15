using Gts.AuthorizationServer.Data;
using Gts.AuthorizationServer.Models.Authentication;
using Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gts.AuthorizationServer.Areas.Identity.Pages.Account;

public class LoginModel(
    SignInManager<ApplicationUser> signInManager,
    ILogger<LoginModel> logger,
    UserManager<ApplicationUser> userManager,
    IUserProvider userProvider)
    : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = null!;

    public IList<AuthenticationScheme> ExternalLogins { get; set; } = null!;

    public string? ReturnUrl { get; set; }

    [TempData]
    public string ErrorMessage { get; set; } = null!;

    private const string ReturnUrlValue = "~/";

    public async Task OnGetAsync(string? returnUrl = null!)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
            ModelState.AddModelError(string.Empty, ErrorMessage);

        returnUrl ??= Url.Content(ReturnUrlValue);

        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content(ReturnUrlValue);

        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (ModelState.IsValid)
        {
            var result = await signInManager.PasswordSignInAsync(Input.UserName, Input.Password, Input.RememberMe, lockoutOnFailure: true);
            var user = await userManager.FindByNameAsync(Input.UserName);

            if (user != null)
            {
                if (!user.IsActive)
                {
                    ModelState.AddModelError(string.Empty, $"Пользователь {user.UserName} деактивирован.");
                    return Page();
                }

                await UpdateLastLoginDate(user);

                userProvider.RoleName = (await userManager.GetRolesAsync(user)).FirstOrDefault() ?? string.Empty;
            }

            if (result.Succeeded)
            {
                AppendCookies();

                logger.LogInformation($"User {Input.UserName} logged in.");

                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }
            if (result.IsLockedOut)
            {
                logger.LogWarning($"User {Input.UserName} account locked out.");

                ModelState.AddModelError(string.Empty, "Превышено количество неудачных попыток ввода.");
                return Page();
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Имя пользователя или пароль указаны неверно.");
                return Page();
            }
        }

        return Page();
    }

    private async Task UpdateLastLoginDate(ApplicationUser user)
    {
        user.LastLoginDate = DateTimeOffset.UtcNow;
        await userManager.UpdateAsync(user);
    }

    private void AppendCookies()
    {
        var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(HexUtils.HexToBinary(LegacyAuthCookieCompatDefaults.DecryptionKey), HexUtils.HexToBinary(LegacyAuthCookieCompatDefaults.ValidationKey));
        var ticketUserName = new FormsAuthenticationTicket(2, Input.UserName, DateTime.Now, DateTime.Now.AddMinutes(525600), true, Input.UserName, "");
        var encryptedTicket = legacyFormsAuthenticationTicketEncryptor.Encrypt(ticketUserName);

        Response.Cookies.Append(LegacyAuthCookieCompatDefaults.CookieUserName, encryptedTicket);
        Response.Cookies.Append(LegacyAuthCookieCompatDefaults.CookieAuth, encryptedTicket);
    }
}
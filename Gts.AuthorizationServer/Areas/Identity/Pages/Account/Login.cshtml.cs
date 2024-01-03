using Gts.AuthorizationServer.Data;
using Gts.AuthorizationServer.Models.Authentication;
using Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gts.AuthorizationServer.Areas.Identity.Pages.Account;

/// <summary>
/// Class LoginModel.
/// Implements the <see cref="PageModel" />
/// </summary>
/// <seealso cref="PageModel" />
public class LoginModel : PageModel
{
    /// <summary>
    /// The sign in manager
    /// </summary>
    private readonly SignInManager<ApplicationUser> _signInManager;

    private readonly UserManager<ApplicationUser> _userManager;

    /// <summary>
    /// The logger
    /// </summary>
    private readonly ILogger<LoginModel> _logger;

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value>The input.</value>
    [BindProperty]
    public InputModel Input { get; set; }

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value>The external logins.</value>
    public IList<AuthenticationScheme> ExternalLogins { get; set; }

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value>The return URL.</value>
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value>The error message.</value>
    [TempData]
    public string ErrorMessage { get; set; }

    public readonly IUserProvider _userProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginModel"/> class.
    /// </summary>
    /// <param name="signInManager">The sign in manager.</param>
    /// <param name="logger">The logger.</param>
    public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger, UserManager<ApplicationUser> userManager, IUserProvider userProvider)
    {
        _signInManager = signInManager;
        _logger = logger;
        _userManager = userManager;
        _userProvider = userProvider;
    }

    /// <summary>
    /// On get as an asynchronous operation.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    public async Task OnGetAsync(string? returnUrl = null!)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
            ModelState.AddModelError(string.Empty, ErrorMessage);

        returnUrl ??= Url.Content("~/");

        // Clear the existing external cookie to ensure a clean login process
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        ReturnUrl = returnUrl;
    }

    /// <summary>
    /// On post as an asynchronous operation.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>A Task&lt;IActionResult&gt; representing the asynchronous operation.</returns>
    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(Input.UserName, Input.Password, Input.RememberMe, lockoutOnFailure: true);
            var user = await _userManager.FindByNameAsync(Input.UserName);

            if (user != null)
            {
                if (!user.IsActive)
                {
                    ModelState.AddModelError(string.Empty, $"Пользователь {user.UserName} деактивирован.");
                    return Page();
                }
                user.LastLoginDate = DateTimeOffset.UtcNow;
                var resultUpdate = await _userManager.UpdateAsync(user);
                _userProvider.RoleName = (await _userManager.GetRolesAsync(user)).FirstOrDefault();

                if (resultUpdate.Succeeded)
                {
                    //todo: Operation result
                }
                else
                {
                    //todo: Operation result
                }
            }

            if (result.Succeeded)
            {
                AppendCookies();

                _logger.LogInformation($"User {Input.UserName} logged in.");

                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning($"User {Input.UserName} account locked out.");

                ModelState.AddModelError(string.Empty, "Превышено количество неудачных попыток ввода.");

                return Page();
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Имя пользователя или пароль указаны неверно.");

                return Page();
            }
        }

        // If we got this far, something failed, redisplay form
        return Page();
    }

    /// <summary>
    /// Appends the cookies.
    /// </summary>
    private void AppendCookies()
    {
        var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(HexUtils.HexToBinary(LegacyAuthCookieCompatDefaults.DecryptionKey), HexUtils.HexToBinary(LegacyAuthCookieCompatDefaults.ValidationKey));
        var ticketUserName = new FormsAuthenticationTicket(2, Input.UserName, DateTime.Now, DateTime.Now.AddMinutes(525600), true, Input.UserName, "");
        var encryptedTicket = legacyFormsAuthenticationTicketEncryptor.Encrypt(ticketUserName);

        Response.Cookies.Append(LegacyAuthCookieCompatDefaults.CookieUserName, encryptedTicket);
        Response.Cookies.Append(LegacyAuthCookieCompatDefaults.CookieAuth, encryptedTicket);
    }
}
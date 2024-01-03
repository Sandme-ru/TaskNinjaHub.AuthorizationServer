// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace Gts.AuthorizationServer.Areas.Identity.Pages.Account;

/// <summary>
/// Class RegisterModel.
/// Implements the <see cref="PageModel" />
/// </summary>
/// <seealso cref="PageModel" />
public class RegisterModel : PageModel
{
    /// <summary>
    /// The sign in manager
    /// </summary>
    private readonly SignInManager<ApplicationUser> _signInManager;
    /// <summary>
    /// The user manager
    /// </summary>
    private readonly UserManager<ApplicationUser> _userManager;
    /// <summary>
    /// The user store
    /// </summary>
    private readonly IUserStore<ApplicationUser> _userStore;
    /// <summary>
    /// The email store
    /// </summary>
    private readonly IUserEmailStore<ApplicationUser> _emailStore;
    /// <summary>
    /// The logger
    /// </summary>
    private readonly ILogger<RegisterModel> _logger;
    /// <summary>
    /// The email sender
    /// </summary>
    private readonly IEmailSender _emailSender;

    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterModel"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="userStore">The user store.</param>
    /// <param name="signInManager">The sign in manager.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="emailSender">The email sender.</param>
    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        IUserStore<ApplicationUser> userStore,
        SignInManager<ApplicationUser> signInManager,
        ILogger<RegisterModel> logger,
        IEmailSender emailSender)
    {
        _userManager = userManager;
        _userStore = userStore;
        _emailStore = GetEmailStore();
        _signInManager = signInManager;
        _logger = logger;
        _emailSender = emailSender;
    }

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
    /// <value>The return URL.</value>
    public string ReturnUrl { get; set; }

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
    public class InputModel
    {
        /// <summary>
        /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future releases.
        /// </summary>
        /// <value>The email.</value>
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        /// <summary>
        /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future releases.
        /// </summary>
        /// <value>The password.</value>
        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        /// <summary>
        /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future releases.
        /// </summary>
        /// <value>The confirm password.</value>
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }


    /// <summary>
    /// On get as an asynchronous operation.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    public async Task OnGetAsync(string returnUrl = null)
    {
        ReturnUrl = returnUrl;
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
    }

    /// <summary>
    /// On post as an asynchronous operation.
    /// </summary>
    /// <param name="returnUrl">The return URL.</param>
    /// <returns>A Task&lt;IActionResult&gt; representing the asynchronous operation.</returns>
    public async Task<IActionResult> OnPostAsync(string returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        if (ModelState.IsValid)
        {
            var user = CreateUser();

            user.CreateDate = DateTimeOffset.UtcNow;

            await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
            var result = await _userManager.CreateAsync(user, Input.Password);
            var identityResult = await _userManager.AddToRoleAsync(user, "Client");

            if (result.Succeeded && identityResult.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");

                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ConfirmEmail",
                    pageHandler: null,
                    values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                else
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
            }
            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
        }

        // If we got this far, something failed, redisplay form
        return Page();
    }

    /// <summary>
    /// Creates the user.
    /// </summary>
    /// <returns>ApplicationUser.</returns>
    /// <exception cref="System.InvalidOperationException">Can't create an instance of '{nameof(ApplicationUser)}'. " +
    ///                                                 $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
    ///                                                 $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml</exception>
    private ApplicationUser CreateUser()
    {
        try
        {
            return Activator.CreateInstance<ApplicationUser>();
        }
        catch
        {
            throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                                                $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                                                $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
        }
    }

    /// <summary>
    /// Gets the email store.
    /// </summary>
    /// <returns>IUserEmailStore&lt;ApplicationUser&gt;.</returns>
    /// <exception cref="System.NotSupportedException">The default UI requires a user store with email support.</exception>
    private IUserEmailStore<ApplicationUser> GetEmailStore()
    {
        if (!_userManager.SupportsUserEmail)
            throw new NotSupportedException("The default UI requires a user store with email support.");
        return (IUserEmailStore<ApplicationUser>)_userStore;
    }
}
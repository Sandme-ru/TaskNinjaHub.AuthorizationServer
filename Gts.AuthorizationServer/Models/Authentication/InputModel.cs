using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.Models.Authentication;

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
    /// <value>The name of the user.</value>
    [Required(ErrorMessage = "Поле «Логин» является обязательным.")]
    [Display(Name = "Логин")]
    public string UserName { get; set; }

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value>The password.</value>
    [Required(ErrorMessage = "Поле «Пароль» является обязательным.")]
    [Display(Name = "Пароль")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    /// <summary>
    /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    /// <value><c>true</c> if [remember me]; otherwise, <c>false</c>.</value>
    [Display(Name = "Запомнить меня")]
    public bool RememberMe { get; set; }
}
using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.Models.Authentication;

public class InputModel
{
    [Required(ErrorMessage = "Поле «Логин» является обязательным.")]
    [Display(Name = "Логин")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "Поле «Пароль» является обязательным.")]
    [Display(Name = "Пароль")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Запомнить меня")]
    public bool RememberMe { get; set; }
}
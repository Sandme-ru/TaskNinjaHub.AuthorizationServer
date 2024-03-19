using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.ViewModels.Authorization;

public class AuthorizeViewModel
{
    [Display(Name = "Application")]
    public string ApplicationName { get; set; } = null!;

    [Display(Name = "Scope")]
    public string Scope { get; set; } = null!;
}

using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.ViewModels.Shared;

public class ErrorViewModel
{
    [Display(Name = "Error")]
    public string Error { get; set; } = null!;

    [Display(Name = "Description")]
    public string ErrorDescription { get; set; } = null!;
}

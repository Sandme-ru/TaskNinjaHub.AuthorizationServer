using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.ViewModels.Shared;

/// <summary>
/// Class ErrorViewModel.
/// </summary>
public class ErrorViewModel
{
    /// <summary>
    /// Gets or sets the error.
    /// </summary>
    /// <value>The error.</value>
    [Display(Name = "Error")]
    public string Error { get; set; }

    /// <summary>
    /// Gets or sets the error description.
    /// </summary>
    /// <value>The error description.</value>
    [Display(Name = "Description")]
    public string ErrorDescription { get; set; }
}

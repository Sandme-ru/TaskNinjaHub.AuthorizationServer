using System.ComponentModel.DataAnnotations;

namespace Gts.AuthorizationServer.ViewModels.Authorization;

/// <summary>
/// Class AuthorizeViewModel.
/// </summary>
public class AuthorizeViewModel
{
    /// <summary>
    /// Gets or sets the name of the application.
    /// </summary>
    /// <value>The name of the application.</value>
    [Display(Name = "Application")]
    public string ApplicationName { get; set; }

    /// <summary>
    /// Gets or sets the scope.
    /// </summary>
    /// <value>The scope.</value>
    [Display(Name = "Scope")]
    public string Scope { get; set; }
}

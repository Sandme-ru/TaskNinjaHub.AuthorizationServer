using Gts.AuthorizationServer.ViewModels.Claim;
using Microsoft.AspNetCore.Identity;

namespace Gts.AuthorizationServer.ViewModels.CombineViewModel;

/// <summary>
/// Class CombineViewModel.
/// </summary>
public class CombineViewModel
{
    /// <summary>
    /// Gets or sets the claims.
    /// </summary>
    /// <value>The claims.</value>
    public List<Gts.AuthorizationServer.Models.Users.ApplicationClaim> Claims { get; set; }

    /// <summary>
    /// Gets or sets the edit model.
    /// </summary>
    /// <value>The edit model.</value>
    public ClaimEditModel EditModel { get; set; }

    /// <summary>
    /// Gets or sets the selected role.
    /// </summary>
    /// <value>The selected role.</value>
    public string? SelectedRole { get; set; }

    /// <summary>
    /// Gets or sets the identity role claims.
    /// </summary>
    /// <value>The identity role claims.</value>
    public List<IdentityRoleClaim<Guid>>? IdentityRoleClaims { get; set; }

    /// <summary>
    /// Gets or sets the russian claim names.
    /// </summary>
    /// <value>The russian claim names.</value>
    public Dictionary<string, string> RussianClaimNames { get; set; }
}
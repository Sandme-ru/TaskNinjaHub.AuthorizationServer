namespace Gts.AuthorizationServer.ViewModels.Claim;

/// <summary>
/// Class ClaimEditModel.
/// </summary>
public class ClaimEditModel
{
    /// <summary>
    /// Gets or sets the name of the claim.
    /// </summary>
    /// <value>The name of the claim.</value>
    public string ClaimName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this <see cref="ClaimEditModel"/> is selected.
    /// </summary>
    /// <value><c>true</c> if selected; otherwise, <c>false</c>.</value>
    public bool Selected { get; set; }
}
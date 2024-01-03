namespace Gts.AuthorizationServer.Services.Store.Claims;

/// <summary>
/// Class ClaimStore.
/// Implements the <see cref="Gts.AuthorizationServer.Services.Store.Claims.IClaimStore" />
/// </summary>
/// <seealso cref="Gts.AuthorizationServer.Services.Store.Claims.IClaimStore" />
public class ClaimStore : IClaimStore
{
    /// <summary>
    /// Gets or sets the name of the role.
    /// </summary>
    /// <value>The name of the role.</value>
    public string? RoleName { get; set; }
}
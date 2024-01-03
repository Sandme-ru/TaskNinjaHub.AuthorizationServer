namespace Gts.AuthorizationServer.Services.Store.Claims;

/// <summary>
/// Interface IClaimStore
/// </summary>
public interface IClaimStore
{
    /// <summary>
    /// Gets or sets the name of the role.
    /// </summary>
    /// <value>The name of the role.</value>
    string? RoleName { get; set; }
}
using Gts.AuthorizationServer.Models.Users;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Data;

/// <summary>
/// Interface IApplicationDbContext
/// </summary>
public interface IApplicationDbContext
{

}

public interface IClaimDbContext
{
    /// <summary>
    /// Gets the application claims.
    /// </summary>
    /// <value>The application claims.</value>
    DbSet<ApplicationClaim> ApplicationClaims { get; }
}
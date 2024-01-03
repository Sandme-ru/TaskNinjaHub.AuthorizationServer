using Gts.AuthorizationServer.Data.DataSeeders;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Gts.AuthorizationServer.Data;

/// <summary>
/// Class ApplicationDbContext.
/// Implements the <see cref="Guid" />
/// </summary>
/// <seealso cref="Guid" />
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>, IApplicationDbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ApplicationDbContext" /> class.
    /// </summary>
    /// <param name="options">The options.</param>
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {

    }
}
public class ClaimDbContext : DbContext, IClaimDbContext
{
    public ClaimDbContext(DbContextOptions<ClaimDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder = DataSeederClaim.SeedData(modelBuilder);
    }

    public DbSet<ApplicationClaim> ApplicationClaims { get; set; }
}
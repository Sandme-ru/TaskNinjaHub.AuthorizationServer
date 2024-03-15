using Gts.AuthorizationServer.Data.DataSeeders;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Context;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options), IApplicationDbContext
{
    public void MigrateDatabase()
    {
        Database.Migrate();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder = DataSeederRole.SeedData(modelBuilder);

        base.OnModelCreating(modelBuilder);
    }
}
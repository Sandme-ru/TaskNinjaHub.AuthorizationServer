using Gts.AuthorizationServer.Data.DataSeeders;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Drawing;

namespace Gts.AuthorizationServer.Context;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {

    }

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
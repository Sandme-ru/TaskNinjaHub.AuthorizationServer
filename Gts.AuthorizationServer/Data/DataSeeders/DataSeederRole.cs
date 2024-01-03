using Gts.AuthorizationServer.Models.Users;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Data.DataSeeders;

public class DataSeederRole
{
    public static ModelBuilder SeedData(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApplicationRole>().HasData(new ApplicationRole { Id = Guid.NewGuid(), Name = "Developer", NormalizedName = "DEVELOPER" });
        modelBuilder.Entity<ApplicationRole>().HasData(new ApplicationRole { Id = Guid.NewGuid(), Name = "Analyst", NormalizedName = "ANALYST" });
        modelBuilder.Entity<ApplicationRole>().HasData(new ApplicationRole { Id = Guid.NewGuid(), Name = "Support", NormalizedName = "SUPPORT" });
        modelBuilder.Entity<ApplicationRole>().HasData(new ApplicationRole { Id = Guid.NewGuid(), Name = "Tester", NormalizedName = "TESTER" });

        return modelBuilder;
    }
}
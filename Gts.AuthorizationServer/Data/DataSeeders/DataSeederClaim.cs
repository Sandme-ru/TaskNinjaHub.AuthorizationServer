using System.Net.Mime;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Data.DataSeeders;

public static class DataSeederClaim
{
    public static ModelBuilder SeedData(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 1, Name = "GetLoggingOperations" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 2, Name = "GetAllWarehouses" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 3, Name = "GetActiveWarehouses" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 4, Name = "AddWarehouse" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 5, Name = "DeleteWarehouse" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 6, Name = "GetCells" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 7, Name = "GetCellsFree" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 8, Name = "AddCell" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 9, Name = "UpdateCell" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 10, Name = "DeleteCell" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 11, Name = "AddOrder" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 12, Name = "MovingOrder" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 13, Name = "PlaceOrderForShipment" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 14, Name = "InventoryOfBalances" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 15, Name = "GetWarehouseHistory" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 16, Name = "ViewUsers" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 17, Name = "AddUser" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 18, Name = "EditUser" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 19, Name = "ChangeUserStatus" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 20, Name = "ViewClaims" });
        modelBuilder.Entity<ApplicationClaim>().HasData(new ApplicationClaim { Id = 21, Name = "CreateClaim" });

        return modelBuilder;
    }
}
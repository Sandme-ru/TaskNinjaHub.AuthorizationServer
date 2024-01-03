﻿// <auto-generated />
using Gts.AuthorizationServer.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Gts.AuthorizationServer.Migrations.ClaimDb
{
    [DbContext(typeof(ClaimDbContext))]
    [Migration("20231101111343_AddClaims")]
    partial class AddClaims
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "7.0.12")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("Gts.AuthorizationServer.Models.Users.ApplicationClaim", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.ToTable("ApplicationClaims");

                    b.HasData(
                        new
                        {
                            Id = 1,
                            Name = "GetLoggingOperations"
                        },
                        new
                        {
                            Id = 2,
                            Name = "GetAllWarehouses"
                        },
                        new
                        {
                            Id = 3,
                            Name = "GetActiveWarehouses"
                        },
                        new
                        {
                            Id = 4,
                            Name = "AddWarehouse"
                        },
                        new
                        {
                            Id = 5,
                            Name = "DeleteWarehouse"
                        },
                        new
                        {
                            Id = 6,
                            Name = "GetCells"
                        },
                        new
                        {
                            Id = 7,
                            Name = "GetCellsFree"
                        },
                        new
                        {
                            Id = 8,
                            Name = "AddCell"
                        },
                        new
                        {
                            Id = 9,
                            Name = "UpdateCell"
                        },
                        new
                        {
                            Id = 10,
                            Name = "DeleteCell"
                        },
                        new
                        {
                            Id = 11,
                            Name = "AddOrder"
                        },
                        new
                        {
                            Id = 12,
                            Name = "MovingOrder"
                        },
                        new
                        {
                            Id = 13,
                            Name = "PlaceOrderForShipment"
                        },
                        new
                        {
                            Id = 14,
                            Name = "InventoryOfBalances"
                        },
                        new
                        {
                            Id = 15,
                            Name = "GetWarehouseHistory"
                        },
                        new
                        {
                            Id = 16,
                            Name = "ViewUsers"
                        },
                        new
                        {
                            Id = 17,
                            Name = "AddUser"
                        },
                        new
                        {
                            Id = 18,
                            Name = "EditUser"
                        },
                        new
                        {
                            Id = 19,
                            Name = "ChangeUserStatus"
                        });
                });
#pragma warning restore 612, 618
        }
    }
}

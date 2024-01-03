using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Gts.AuthorizationServer.Migrations
{
    /// <inheritdoc />
    public partial class AddRoleSeed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { new Guid("a2392d6b-5103-4683-9fcd-aa0b70f98f53"), null, "Tester", "TESTER" },
                    { new Guid("bc63b7f5-4979-4c6c-811f-442b9a9a73e1"), null, "Support", "SUPPORT" },
                    { new Guid("c0a6ff83-f73c-40d3-8bb0-3e77ac8a4cef"), null, "Analyst", "ANALYST" },
                    { new Guid("fc43cc43-ac11-42be-b5e7-e8fa2bc69c75"), null, "Developer", "DEVELOPER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("a2392d6b-5103-4683-9fcd-aa0b70f98f53"));

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("bc63b7f5-4979-4c6c-811f-442b9a9a73e1"));

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("c0a6ff83-f73c-40d3-8bb0-3e77ac8a4cef"));

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("fc43cc43-ac11-42be-b5e7-e8fa2bc69c75"));
        }
    }
}

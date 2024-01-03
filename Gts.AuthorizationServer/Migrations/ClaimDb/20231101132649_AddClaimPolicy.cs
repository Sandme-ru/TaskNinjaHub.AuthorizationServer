using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Gts.AuthorizationServer.Migrations.ClaimDb
{
    /// <inheritdoc />
    public partial class AddClaimPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "ApplicationClaims",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 20, "ViewClaims" },
                    { 21, "CreateClaim" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 20);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 21);
        }
    }
}

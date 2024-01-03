using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Gts.AuthorizationServer.Migrations.ClaimDb
{
    /// <inheritdoc />
    public partial class InitClaims : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ApplicationClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApplicationClaims", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "ApplicationClaims",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 1, "GetLoggingOperations" },
                    { 2, "GetAllWarehouses" },
                    { 3, "GetActiveWarehouses" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApplicationClaims");
        }
    }
}

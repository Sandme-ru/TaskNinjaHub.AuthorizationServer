using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Gts.AuthorizationServer.Migrations.ClaimDb
{
    /// <inheritdoc />
    public partial class AddClaims : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "ApplicationClaims",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 4, "AddWarehouse" },
                    { 5, "DeleteWarehouse" },
                    { 6, "GetCells" },
                    { 7, "GetCellsFree" },
                    { 8, "AddCell" },
                    { 9, "UpdateCell" },
                    { 10, "DeleteCell" },
                    { 11, "AddOrder" },
                    { 12, "MovingOrder" },
                    { 13, "PlaceOrderForShipment" },
                    { 14, "InventoryOfBalances" },
                    { 15, "GetWarehouseHistory" },
                    { 16, "ViewUsers" },
                    { 17, "AddUser" },
                    { 18, "EditUser" },
                    { 19, "ChangeUserStatus" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 4);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 5);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 6);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 7);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 8);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 9);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 10);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 11);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 12);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 13);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 14);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 15);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 16);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 17);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 18);

            migrationBuilder.DeleteData(
                table: "ApplicationClaims",
                keyColumn: "Id",
                keyValue: 19);
        }
    }
}

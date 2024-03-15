using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class AdminController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager) : Controller
{
    [HttpPost("AddRole")]
    public async Task<IActionResult> AddRoleAsync([FromQuery] string roleName)
    {
        var roleExists = await roleManager.RoleExistsAsync(roleName);

        if (!roleExists)
        {
            var result = await roleManager.CreateAsync(new ApplicationRole
            {
                Id = Guid.NewGuid(),
                Name = roleName
            });

            return Ok(result);
        }

        return BadRequest(roleExists);
    }

    [HttpPost("AddFakeAdmin")]
    public async Task<IActionResult> AddFakeAdmin()
    {
        var admin = new ApplicationUser
        {
            Email = "admin@mail.ru",
            UserName = "admin@mail.ru",
            FirstName = "Admin",
            LastName = "Admin",
            MiddleName = "Admin",
            PhoneNumber = "89178881788",
        };

        var identityResult = await userManager.CreateAsync(admin, "qweASD123!@#qwe");

        if (identityResult.Succeeded)
            await userManager.AddToRoleAsync(admin, "Admin");

        return Ok(identityResult);
    }
}
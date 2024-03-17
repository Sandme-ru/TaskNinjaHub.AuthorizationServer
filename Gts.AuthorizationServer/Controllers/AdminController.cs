using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class AdminController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager) : Controller
{
    [HttpPost("EditUser")]
    public async Task<IActionResult> EditUser([FromBody] AuthorDto user)
    {
        var editedUser = await userManager.FindByIdAsync(user.Id.ToString());

        if (editedUser == null)
        {
            return NotFound();
        }

        if (editedUser.Email != user.Name)
        {
            editedUser.Email = user.Name;
        }

        if (!string.IsNullOrEmpty(user.Password))
        {
            var passwordValidator = new PasswordValidator<ApplicationUser>();
            var identityResult = await passwordValidator.ValidateAsync(userManager, editedUser, user.Password);
            if (identityResult.Succeeded)
            {
                var token = await userManager.GeneratePasswordResetTokenAsync(editedUser);
                var passwordChangeResult = await userManager.ResetPasswordAsync(editedUser, token, user.Password);
                if (!passwordChangeResult.Succeeded)
                {
                    return BadRequest("Password is invalid");
                }
            }
            else
            {
                return BadRequest(string.Join('\n', identityResult.Errors));
            }
        }

        var result = await userManager.UpdateAsync(editedUser);
        if (!result.Succeeded)
        {
            return BadRequest(string.Join('\n', result.Errors));
        }

        return Ok();
    }

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
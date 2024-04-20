using Gts.AuthorizationServer.Models.Bases;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class AdminController(UserManager<ApplicationUser> userManager, UserManager<UserDto> userDtoManager, RoleManager<ApplicationRole> roleManager, IdentityDbContext context) : Controller
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

    [HttpGet("GetRoles")]
    public async Task<List<IdentityRole>> GetRolesAsync()
    {
        var roles = await context.Roles.ToListAsync();

        if (roles.Any())
            return roles;

        return new List<IdentityRole>();
    }

    [HttpPut("EditRole")]
    public async Task<bool> EditRoleAsync(ApplicationRole role)
    {
        var roleExists = await roleManager.FindByIdAsync(role.Id.ToString());

        if (roleExists != null)
        {
            await roleManager.UpdateAsync(role);
            return true;
        }

        return false;
    }

    [HttpDelete("DeleteRole")]
    public async Task<IActionResult> DeleteRoleAsync([FromQuery] string roleId)
    {
        var roleExists = await roleManager.FindByIdAsync(roleId);

        if (roleExists != null)
        {
            var result = roleManager.DeleteAsync(roleExists);
            return Ok(result);
        }

        return BadRequest(roleExists);
    }

    [HttpGet("GetUsers")]
    public async Task<List<IdentityUser>> GetUsersAsync()
    {
        var users = await context.Users.ToListAsync();

        if (users.Any())
            return users;

        return new List<IdentityUser>();
    }

    [HttpDelete("DeleteUser")]
    public async Task<bool> DeleteUserAsync(string id)
    {
        var user = await userManager.FindByIdAsync(id);

        if (user != null!)
        {
            await userManager.DeleteAsync(user);
            return true;
        }
        else
            return false;
    }

    [HttpPost("EditUser")]
    public async Task<IActionResult> EditUserAsync([FromBody] AuthorDto user)
    {
        var editedUser = await userManager.FindByIdAsync(user.Id.ToString());

        if (editedUser == null)
            return NotFound();

        if (editedUser.Email != user.Name)
            editedUser.Email = user.Name;

        if (editedUser.LocalizationType != user.LocalizationType)
            editedUser.LocalizationType = user.LocalizationType;

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
                    return BadRequest(new BaseResult
                    {
                        Success = false,
                        Error = "Password is invalid"
                    });
                }
            }
            else
            {
                return BadRequest(new BaseResult
                {
                    Success = false,
                    Error = string.Join('\n', identityResult.Errors.Select(error => error.Description))
                });
            }
        }

        var result = await userManager.UpdateAsync(editedUser);
        if (!result.Succeeded)
        {
            return BadRequest(new BaseResult
            {
                Success = false,
                Error = string.Join('\n', result.Errors.Select(error => error.Description))
            });
        }

        return Ok(new BaseResult
        {
            Success = true
        });
    }

    [HttpPost("AddUser")]
    public async Task<IActionResult> AddUserAsync(UserDto user)
    {
        var identityResult = await userDtoManager.CreateAsync(user, user.Password);

        if (identityResult.Succeeded)
            await userDtoManager.AddToRoleAsync(user, user.Role);

        return Ok(identityResult);
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
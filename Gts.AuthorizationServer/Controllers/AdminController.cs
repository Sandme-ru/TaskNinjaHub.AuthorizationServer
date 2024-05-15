using Gts.AuthorizationServer.Context;
using Gts.AuthorizationServer.Models.Bases;
using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class AdminController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, ApplicationDbContext context) : Controller
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

        return BadRequest("Такая роль уже существует");
    }

    [HttpGet("GetRoles")]
    public async Task<List<ApplicationRole>> GetRolesAsync()
    {
        var roles = await context.Roles.ToListAsync();

        if (roles.Any())
            return roles;

        return new List<ApplicationRole>();
    }

    [HttpPut("EditRole")]
    public async Task<bool> EditRoleAsync([FromQuery] string roleId, [FromQuery] string newName)
    {
        var roleExists = await roleManager.FindByIdAsync(roleId.ToString());

        if (roleExists != null)
        {
            roleExists.Name = newName;
            await roleManager.UpdateAsync(roleExists);
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
    public async Task<List<ApplicationUser>> GetUsersAsync()
    {
        var users = await context.Users.ToListAsync();

        if (users.Any())
            return users;

        return new List<ApplicationUser>();
    }

    [HttpGet("GetUserRole")]
    public async Task<IList<string>> GetUserRoleAsync(string userId)
    {
        var user = await userManager.FindByIdAsync(userId);

        var role = await userManager.GetRolesAsync(user);

        if (role != null)
            return role;

        return new List<string>();
    }

    [HttpDelete("DeleteUser")]
    public async Task<bool> DeleteUserAsync([FromQuery] string id)
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

    [HttpPut("EditUser")]
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

    [HttpPost("EditUserInfo")]
    public async Task<IActionResult> EditUserInfoAsync([FromBody] UserDto userDto)
    {
        var editedUser = await userManager.FindByEmailAsync(userDto.Email.ToString());

        if (editedUser == null)
            return NotFound();

        editedUser.Email = userDto.Email;
        editedUser.FirstName = userDto.FirstName;
        editedUser.LastName = userDto.LastName;
        editedUser.MiddleName = userDto.MiddleName;
        editedUser.UserName = userDto.UserName;
        editedUser.PhoneNumber = userDto.PhoneNumber;


        var identityUserResult = await userManager.UpdateAsync(editedUser);

        if (!string.IsNullOrEmpty(userDto.Password))
        {
            var passwordValidator = new PasswordValidator<ApplicationUser>();
            var identityResult = await passwordValidator.ValidateAsync(userManager, editedUser, userDto.Password);
            if (identityResult.Succeeded)
            {
                var token = await userManager.GeneratePasswordResetTokenAsync(editedUser);
                var passwordChangeResult = await userManager.ResetPasswordAsync(editedUser, token, userDto.Password);
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

        if (identityUserResult.Succeeded)
        {
            var roles = await userManager.GetRolesAsync(editedUser);
            await userManager.RemoveFromRolesAsync(editedUser, roles);
            await userManager.AddToRoleAsync(editedUser, userDto.Role);
        }

        return Ok(identityUserResult);
    }

    [HttpPost("AddUser")]
    public async Task<IActionResult> AddUserAsync([FromBody] UserDto userDto)
    {
        var user = new ApplicationUser
        {
            Email = userDto.Email,
            FirstName = userDto.FirstName,
            LastName = userDto.LastName,
            MiddleName = userDto.MiddleName,
            UserName = userDto.UserName,
            PhoneNumber = userDto.PhoneNumber
        };

        var identityResult = await userManager.CreateAsync(user, userDto.Password);

        if (identityResult.Succeeded)
            await userManager.AddToRoleAsync(user, userDto.Role);
        else
            return BadRequest("Произошла ошибка на стороне сервера авторизации. Обратитесь в службу поддержки shvyrkalovm@mail.ru.");

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
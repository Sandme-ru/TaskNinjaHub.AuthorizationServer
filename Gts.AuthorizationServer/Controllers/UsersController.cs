using Gts.AuthorizationServer.Models.Users;
using Gts.AuthorizationServer.ViewModels.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

[Route("[controller]/[action]")]
public class UsersController(
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    ILogger<UserinfoController> logger,
    IAuthorizationService authorizationService)
    : Controller
{
    public IActionResult Index() => View(userManager.Users.ToList());

    public async Task<IActionResult> Create()
    {
        ViewBag.Roles = await roleManager.Roles.ToListAsync();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Create(CreateUserViewModel model)
    {
        logger.LogInformation($"This is Create method of UsersController");

        if (ModelState.IsValid)
        {
            var createdUser = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                MiddleName = model.MiddleName,
                PhoneNumber = model.PhoneNumber,
                CreateDate = DateTimeOffset.UtcNow
            };

            var result = await userManager.CreateAsync(createdUser, model.Password);
            var identityResult = await userManager.AddToRoleAsync(createdUser, model.SelectedRole);

            if (result.Succeeded && identityResult.Succeeded)
                return RedirectToAction("Index");
            else
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);
        }

        ViewBag.Roles = await roleManager.Roles.ToListAsync();
        return View(model);
    }

    public async Task<IActionResult> Edit(string id)
    {
        logger.LogInformation($"This is Edit method of UsersController");

        ViewBag.Roles = await roleManager.Roles.ToListAsync();

        var editedUser = await userManager.FindByIdAsync(id);

        if (editedUser == null)
            return NotFound();
        
        var model = new EditUserViewModel
        {
            Id = editedUser.Id,
            Email = editedUser.Email!,
            FirstName = editedUser.FirstName!,
            LastName = editedUser.LastName!,
            MiddleName = editedUser.MiddleName!,
            PhoneNumber = editedUser.PhoneNumber!,
            IsActive = editedUser.IsActive,
            SelectedRole = (await userManager.GetRolesAsync(editedUser)).FirstOrDefault()!
        };

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(EditUserViewModel model)
    {
        logger.LogInformation($"This is Edit method of UsersController");

        if (ModelState.IsValid)
        {
            var user = await userManager.FindByIdAsync(model.Id.ToString());

            if (user != null)
            {
                user.Email = model.Email;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.MiddleName = model.MiddleName;
                user.PhoneNumber = model.PhoneNumber;
                user.IsActive = model.IsActive;

                var roles = await userManager.GetRolesAsync(user);
                var removeRolesResult = await userManager.RemoveFromRolesAsync(user, roles);

                var addRoleResult = await userManager.AddToRoleAsync(user, model.SelectedRole);
                var updateUserResult = await userManager.UpdateAsync(user);

                if (removeRolesResult.Succeeded && addRoleResult.Succeeded && updateUserResult.Succeeded)
                    return RedirectToAction("Index");
                else
                    foreach (var error in updateUserResult.Errors)
                        ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        ViewBag.Roles = await roleManager.Roles.ToListAsync();

        return View(model);
    }

    [HttpPost]
    public async Task<ActionResult> ChangeStatus(string id)
    {
        var authorizationResult = await authorizationService.AuthorizeAsync(User, "ChangeUserStatus");

        if (authorizationResult.Succeeded)
        {
            logger.LogInformation($"This is Delete method of UsersController");
            var user = await userManager.FindByIdAsync(id);
            if (user != null)
            {
                user.IsActive = !user.IsActive;
                var result = await userManager.UpdateAsync(user);
                if (result.Succeeded)
                    return RedirectToAction("Index");
            }
            else
                ModelState.AddModelError(string.Empty, "Ошибка деактивации");
        }
        else
            ModelState.AddModelError(string.Empty, "У вас нет прав на совершение этой операции");

        return RedirectToAction("Index");
    }
}
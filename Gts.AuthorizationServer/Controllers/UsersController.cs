using Gts.AuthorizationServer.Models.Users;
using Gts.AuthorizationServer.ViewModels.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Gts.AuthorizationServer.Controllers;

[Route("auth-server/[controller]/[action]")]
public class UsersController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    private readonly RoleManager<ApplicationRole> _roleManager;

    private readonly ILogger<UserinfoController> _logger;

    private readonly IAuthorizationService _authorizationService;



    public UsersController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, ILogger<UserinfoController> logger, IAuthorizationService authorizationService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _authorizationService = authorizationService;
    }

    public IActionResult Index() => View(_userManager.Users.ToList());

    public async Task<IActionResult> Create()
    {
        ViewBag.Roles = await _roleManager.Roles.ToListAsync();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Create(CreateUserViewModel model)
    {
        _logger.LogInformation($"This is Create method of UsersController");
        if (ModelState.IsValid)
        {
            var user = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                MiddleName = model.MiddleName,
                PhoneNumber = model.PhoneNumber,
                CreateDate = DateTimeOffset.UtcNow
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            var identityResult = await _userManager.AddToRoleAsync(user, model.SelectedRole);

            if (result.Succeeded)
                return RedirectToAction("Index");
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
        }
        ViewBag.Roles = await _roleManager.Roles.ToListAsync();
        return View(model);
    }

    public async Task<IActionResult> Edit(string id)
    {
        _logger.LogInformation($"This is Edit method of UsersController");
        var user = await _userManager.FindByIdAsync(id);

        if (user == null)
            return NotFound();

        ViewBag.Roles = await _roleManager.Roles.ToListAsync();

        var model = new EditUserViewModel
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            MiddleName = user.MiddleName,
            PhoneNumber = user.PhoneNumber,
            IsActive = user.IsActive,
            SelectedRole = (await _userManager.GetRolesAsync(user)).FirstOrDefault()!
        };
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(EditUserViewModel model)
    {
        _logger.LogInformation($"This is Edit method of UsersController");
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByIdAsync(model.Id.ToString());

            if (user != null)
            {
                user.Email = model.Email;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.MiddleName = model.MiddleName;
                user.PhoneNumber = model.PhoneNumber;
                user.IsActive = model.IsActive;

                var roles = await _userManager.GetRolesAsync(user);
                var removeRolesResult = await _userManager.RemoveFromRolesAsync(user, roles);

                var addRoleResult = await _userManager.AddToRoleAsync(user, model.SelectedRole);
                var updateUserResult = await _userManager.UpdateAsync(user);

                if (removeRolesResult.Succeeded && addRoleResult.Succeeded && updateUserResult.Succeeded)
                    return RedirectToAction("Index");
                else
                {
                    foreach (var error in updateUserResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
        }
        ViewBag.Roles = await _roleManager.Roles.ToListAsync();

        return View(model);
    }

    [HttpPost]
    public async Task<ActionResult> ChangeStatus(string id)
    {
        var authorizationResult = await _authorizationService.AuthorizeAsync(User, "ChangeUserStatus");

        if (authorizationResult.Succeeded)
        {
            _logger.LogInformation($"This is Delete method of UsersController");
            var user = await _userManager.FindByIdAsync(id);
            if (user != null)
            {
                user.IsActive = !user.IsActive;
                var result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                    return RedirectToAction("Index");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "������ �����������");
            }
        }
        else
        {
            ModelState.AddModelError(string.Empty, "� ��� ��� ���� �� ���������� ���� ��������");
        }
        return RedirectToAction("Index");
    }
}
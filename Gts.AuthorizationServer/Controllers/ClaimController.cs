using System.Security.Claims;
using Gts.AuthorizationServer.Data;
using Gts.AuthorizationServer.Data.AuthorizationPolicy;
using Gts.AuthorizationServer.Models.Users;
using Gts.AuthorizationServer.Services.Store.Claims;
using Gts.AuthorizationServer.ViewModels.Claim;
using Gts.AuthorizationServer.ViewModels.CombineViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

public class ClaimController : Controller
{
    private readonly ClaimDbContext _claimDbContext;

    private readonly ApplicationDbContext _applicationDbContext;

    private readonly RoleManager<ApplicationRole> _roleManager;

    private readonly UserManager<ApplicationUser> _userManager;

    private readonly IAuthorizationPolicyProviderService _authorizationPolicyProviderService;

    private readonly IClaimStore _claimStore;

    private readonly IAuthorizationService _authorizationService;

    public ClaimController(ClaimDbContext context, ApplicationDbContext applicationDbContext, RoleManager<ApplicationRole> roleManager, IClaimStore claimStore, IAuthorizationPolicyProviderService authorizationPolicyProviderService, IAuthorizationService authorizationService, UserManager<ApplicationUser> userManager)
    {
        _claimDbContext = context;
        _applicationDbContext = applicationDbContext;
        _roleManager = roleManager;
        _claimStore = claimStore;
        _authorizationPolicyProviderService = authorizationPolicyProviderService;
        _authorizationService = authorizationService;
        _userManager = userManager;
    }


    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var claims = _applicationDbContext.RoleClaims.ToList();
        if (User.Identity != null)
        {
            var role = (await _userManager.GetRolesAsync(await _userManager.FindByNameAsync(User.Identity.Name!))).FirstOrDefault();
            var flag = claims.Any(c => c.ClaimType == role && c.ClaimValue == "ViewClaims");

            if(flag)
            {
                ViewBag.Roles = _applicationDbContext.Roles.ToList();
                var model = new CombineViewModel
                {
                    EditModel = new ClaimEditModel(),
                    SelectedRole = "Роль не выбрана"
                };

                model.Claims = (model.SelectedRole != "Роль не выбрана")
                    ? _claimDbContext.ApplicationClaims.ToList()
                    : new List<ApplicationClaim>();
                return View(model);
            }
            else
            {
                return Forbid();
            }
        }

        return NotFound();
    }

    [HttpPost]
    [Authorize(Policy = "CreateClaim")]
    public async Task<IActionResult> Create(string[] selectedNames)
    {
        if (_claimStore.RoleName != null)
        {
            var role = await _roleManager.FindByNameAsync(_claimStore.RoleName);
            var claims = new List<string>();

            if (role != null)
            {
                claims = (await _roleManager.GetClaimsAsync(role)).Select(c => c.Value).ToList();

                var allClaims = _claimDbContext.ApplicationClaims.Select(c => c.Name).ToList();
                var exceptedList = allClaims.Except(selectedNames).ToList();

                foreach (var claim in exceptedList)
                {
                    var result = (await _roleManager.GetClaimsAsync(role)).FirstOrDefault(c => c.Value == claim)!;
                    if (result != null)
                        await _roleManager.RemoveClaimAsync(role, result);
                }

                foreach (var selectedName in selectedNames)
                {
                    var contains = claims.Contains(selectedName);
                    if (!contains)
                        await _roleManager.AddClaimAsync(role, new Claim(_claimStore.RoleName, selectedName));
                }
            }
        }

        var model = FillModel();

        return View("Index", model);
    }

    [HttpPost]
    public async Task<IActionResult> SelectedRole(string selectedRole)
    {
        _claimStore.RoleName = selectedRole;

        var model = FillModel();

        var roleClaims = _applicationDbContext.RoleClaims.ToList();
        var role = await _roleManager.FindByNameAsync(_claimStore.RoleName);

        var identityRoleClaims = roleClaims.Where(r => role != null && r.RoleId == role.Id).ToList();
        model.IdentityRoleClaims = identityRoleClaims;

        return View("Index", model);
    }

    private CombineViewModel FillModel()
    {
        ViewBag.Roles = _applicationDbContext.Roles.ToList();
        var model = new CombineViewModel
        {
            Claims = _claimDbContext.ApplicationClaims.ToList(),
            EditModel = new ClaimEditModel(),
            SelectedRole = "Роль не выбрана",
            RussianClaimNames = new Dictionary<string, string>
            {
                { "GetLoggingOperations", "Получить список операции по складу" },
                { "GetAllWarehouses", "Получить список всех складов" },
                { "GetActiveWarehouses", "Получить список активных складов" },
                { "AddWarehouse", "Добавить склад" },
                { "DeleteWarehouse", "Удалить склад" },
                { "GetCells", "Получить список всех ячеек" },
                { "GetCellsFree", "Получить список свободных ячеек" },
                { "AddCell", "Добавить ячейку" },
                { "UpdateCell", "Обновить ячейку" },
                { "DeleteCell", "Удалить ячейку" },
                { "AddOrder", "Добавить заказ" },
                { "MovingOrder", "Передвижение заказа" },
                { "PlaceOrderForShipment", "Разместить заказ для отгрузки" },
                { "InventoryOfBalances", "Инвентаризация остатков по складу" },
                { "GetWarehouseHistory", "История движения заказа" },
                { "ViewUsers", "Просмотр пользователей" },
                { "AddUser", "Добавить пользователя" },
                { "EditUser", "Редактировать пользователя" },
                { "ChangeUserStatus", "Изменить статус пользователя" },
                { "ViewClaims", "Просмотр возможностей пользователя" },
                { "CreateClaim", "Изменить возможность пользователя" }
            }
        };

        return model;
    }

    public async Task<IActionResult> CreateRole(string roleName)
    {
        var result = await _roleManager.CreateAsync(new ApplicationRole
        {
            Id = Guid.NewGuid(),
            Name = roleName
        });

        var model = FillModel();
        if (result.Succeeded)
            return RedirectToAction("Index", model);
        else
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        return View(model);
    }
}
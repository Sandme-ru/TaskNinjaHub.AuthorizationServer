using Gts.AuthorizationServer.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AdminController : Controller
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AdminController> _logger;

        public AdminController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, ILogger<AdminController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRoleAsync([FromQuery] string roleName)
        {
            _logger.LogInformation($"This is AddRole method of Admin controller");
            var roleExists = await _roleManager.RoleExistsAsync(roleName);

            if (!roleExists)
            {
                var result = await _roleManager.CreateAsync(new ApplicationRole
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
            _logger.LogInformation($"This is AddFakeAdmin method of Admin controller");
            var admin = new ApplicationUser
            {
                Email = "admin@mail.ru",
                UserName = "admin@mail.ru",
                FirstName = "Admin",
                LastName = "Admin",
                MiddleName = "Admin",
                PhoneNumber = "89178881788",
            };

            var identityResult = await _userManager.CreateAsync(admin, "qweASD123!@#qwe");

            if (identityResult.Succeeded)
                await _userManager.AddToRoleAsync(admin, "Admin");

            return Ok(identityResult);
        }
    }
}

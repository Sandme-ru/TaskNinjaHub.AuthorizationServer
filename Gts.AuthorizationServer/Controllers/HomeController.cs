using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

[Route("")]
public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}

using Gts.AuthorizationServer.ViewModels.Shared;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

public class ErrorController(ILogger<ErrorController> logger) : Controller
{
    [Route("error")]
    [NonAction]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        var response = HttpContext.GetOpenIddictServerResponse();
        if (response == null)
        {
            return View(new ErrorViewModel());
        }

        logger.LogError($"Error: {response.ErrorDescription}");
        return View(new ErrorViewModel
        {
            Error = response.Error!,
            ErrorDescription = response.ErrorDescription!
        });
    }
}

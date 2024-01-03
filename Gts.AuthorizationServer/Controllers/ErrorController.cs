using Gts.AuthorizationServer.ViewModels.Shared;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Gts.AuthorizationServer.Controllers;

/// <summary>
/// Class ErrorController.
/// Implements the <see cref="Controller" />
/// </summary>
/// <seealso cref="Controller" />
public class ErrorController : Controller
{
    private readonly ILogger<ErrorController> _logger;

    public ErrorController(ILogger<ErrorController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Errors this instance.
    /// </summary>
    /// <returns>IActionResult.</returns>
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
        _logger.LogError($"Error: {response.ErrorDescription}");
        return View(new ErrorViewModel
        {
            Error = response.Error,
            ErrorDescription = response.ErrorDescription
        });
    }
}

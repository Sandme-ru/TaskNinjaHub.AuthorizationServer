using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;

namespace Gts.AuthorizationServer.Helpers;

/// <summary>
/// Class FormValueRequiredAttribute. This class cannot be inherited.
/// Implements the <see cref="ActionMethodSelectorAttribute" />
/// </summary>
/// <seealso cref="ActionMethodSelectorAttribute" />
public sealed class FormValueRequiredAttribute : ActionMethodSelectorAttribute
{
    /// <summary>
    /// The name
    /// </summary>
    private readonly string _name;

    /// <summary>
    /// Initializes a new instance of the <see cref="FormValueRequiredAttribute"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    public FormValueRequiredAttribute(string name)
    {
        _name = name;
    }

    /// <summary>
    /// Determines whether [is valid for request] [the specified context].
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="action">The action.</param>
    /// <returns><c>true</c> if [is valid for request] [the specified context]; otherwise, <c>false</c>.</returns>
    public override bool IsValidForRequest(RouteContext context, ActionDescriptor action)
    {
        if (string.Equals(context.HttpContext.Request.Method, "GET", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "HEAD", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "DELETE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "TRACE", StringComparison.OrdinalIgnoreCase))
            return false;

        if (string.IsNullOrEmpty(context.HttpContext.Request.ContentType))
            return false;

        if (!context.HttpContext.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return false;

        return !string.IsNullOrEmpty(context.HttpContext.Request.Form[_name]);
    }
}

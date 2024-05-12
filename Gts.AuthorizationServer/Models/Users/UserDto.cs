using Gts.AuthorizationServer.Models.Localization;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel;

namespace Gts.AuthorizationServer.Models.Users;

public class UserDto
{
    public virtual string UserName { get; set; }
    public virtual string Email { get; set; }
    public virtual string PhoneNumber { get; set; }
    public string FirstName { get; set; }

    public string LastName { get; set; }

    public string MiddleName { get; set; }

    public string Password { get; set; }

    public string Role { get; set; }
}
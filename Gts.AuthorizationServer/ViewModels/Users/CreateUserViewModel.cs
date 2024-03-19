using Gts.AuthorizationServer.Models.Localization;

namespace Gts.AuthorizationServer.ViewModels.Users;

public class CreateUserViewModel
{
    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public string FirstName { get; set; } = null!;

    public string LastName { get; set; } = null!;

    public string MiddleName { get; set; } = null!;

    public string PhoneNumber { get; set; } = null!;

    public string SelectedRole { get; set; } = null!;

    public LocalizationType SelectedLocalizationType { get; set; }
}
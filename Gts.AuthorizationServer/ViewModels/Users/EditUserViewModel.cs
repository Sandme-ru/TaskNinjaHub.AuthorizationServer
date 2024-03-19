using Gts.AuthorizationServer.Models.Localization;

namespace Gts.AuthorizationServer.ViewModels.Users;

public class EditUserViewModel
{
    public Guid Id { get; set; }

    public string Email { get; set; } = null!;

    public string FirstName { get; set; } = null!;

    public string LastName { get; set; } = null!;

    public string MiddleName { get; set; } = null!;

    public string PhoneNumber { get; set; } = null!;

    public bool IsActive { get; set; }

    public string SelectedRole { get; set; } = null!;

    public LocalizationType SelectedLocalizationType { get; set; }
}
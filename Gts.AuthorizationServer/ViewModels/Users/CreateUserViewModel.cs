namespace Gts.AuthorizationServer.ViewModels.Users;

public class CreateUserViewModel
{
    public string Email { get; set; }

    public string Password { get; set; }

    public string FirstName { get; set; }

    public string LastName { get; set; }

    public string MiddleName { get; set; }

    public string PhoneNumber { get; set; }

    public string SelectedRole { get; set; }
}
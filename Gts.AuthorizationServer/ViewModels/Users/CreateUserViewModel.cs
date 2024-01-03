namespace Gts.AuthorizationServer.ViewModels.Users;

/// <summary>
/// Class CreateUserViewModel.
/// </summary>
public class CreateUserViewModel
{
    /// <summary>
    /// Gets or sets the email.
    /// </summary>
    /// <value>The email.</value>
    public string Email { get; set; }

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    /// <value>The password.</value>
    public string Password { get; set; }

    /// <summary>
    /// Gets or sets the first name.
    /// </summary>
    /// <value>The first name.</value>
    public string FirstName { get; set; }

    /// <summary>
    /// Gets or sets the last name.
    /// </summary>
    /// <value>The last name.</value>
    public string LastName { get; set; }

    /// <summary>
    /// Gets or sets the name of the middle.
    /// </summary>
    /// <value>The name of the middle.</value>
    public string MiddleName { get; set; }

    /// <summary>
    /// Gets or sets the phone number.
    /// </summary>
    /// <value>The phone number.</value>
    public string PhoneNumber { get; set; }
}
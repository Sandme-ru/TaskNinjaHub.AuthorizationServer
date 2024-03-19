using Gts.AuthorizationServer.Models.Localization;

namespace Gts.AuthorizationServer.Models.Users;

public class AuthorDto
{
    public Guid Id { get; set; }

    public string Name { get; set; }

    public string Password { get; set; }

    public LocalizationType LocalizationType { get; set; }
}
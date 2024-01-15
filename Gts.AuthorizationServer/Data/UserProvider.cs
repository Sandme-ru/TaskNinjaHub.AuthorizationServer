namespace Gts.AuthorizationServer.Data;

public interface IUserProvider
{
    string? RoleName { get; set; }
}

public class UserProvider : IUserProvider
{
    public string? RoleName { get; set; }
}
namespace Gts.AuthorizationServer.Data.AuthorizationPolicy;

public class AuthorizationPolicyConfig
{
    public string Name { get; set; }

    public Dictionary<string, string> Claims { get; set; }
}
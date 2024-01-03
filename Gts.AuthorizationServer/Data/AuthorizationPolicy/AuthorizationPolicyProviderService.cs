using Newtonsoft.Json;

namespace Gts.AuthorizationServer.Data.AuthorizationPolicy;

public interface IAuthorizationPolicyProviderService
{
    List<AuthorizationPolicyConfig> GetAuthorizationPolicies();
}

public class AuthorizationPolicyProviderService : IAuthorizationPolicyProviderService
{
    private readonly IConfiguration _configuration;

    private readonly string _filePath;

    public AuthorizationPolicyProviderService(IConfiguration configuration)
    {
        _configuration = configuration;
        _filePath = _configuration.GetValue<string>("AuthorizationPoliciesFilePath")!;
    }

    public List<AuthorizationPolicyConfig> GetAuthorizationPolicies()
    {
        string jsonFilePath = "authorizationPolicies.json";

        // Считывание JSON из файла
        string json = File.ReadAllText(jsonFilePath);

        // Десериализация JSON в объект
        List<AuthorizationPolicyConfig> policies = JsonConvert.DeserializeObject<List<AuthorizationPolicyConfig>>(json);
        return policies;
    }

    public void AddAuthorizationPolicy(AuthorizationPolicyConfig newPolicy)
    {
        var policies = GetAuthorizationPolicies();
        policies.Add(new AuthorizationPolicyConfig
        {
            Name = newPolicy.Name,
            Claims = newPolicy.Claims
        });

        var json = JsonConvert.SerializeObject(policies, Formatting.Indented);
        File.WriteAllText(_filePath, json);
    }
}
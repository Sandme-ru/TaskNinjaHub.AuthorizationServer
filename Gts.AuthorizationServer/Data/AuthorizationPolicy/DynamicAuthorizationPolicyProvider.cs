using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Gts.AuthorizationServer.Data.AuthorizationPolicy;

public class DynamicAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
    private DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; set; }

    private IAuthorizationPolicyProviderService PolicyProviderService { get; set; }

    public DynamicAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options, IAuthorizationPolicyProviderService policyProviderService)
    {
        FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        PolicyProviderService = policyProviderService;
    }

    public async Task<Microsoft.AspNetCore.Authorization.AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        var policies = PolicyProviderService.GetAuthorizationPolicies();

        var policyConfig = policies.FirstOrDefault(p => p.Name == policyName);

        if (policyConfig != null)
        {
            var policyBuilder = new AuthorizationPolicyBuilder();
            foreach (var claim in policyConfig.Claims)
            {
                policyBuilder.RequireClaim(claim.Key, claim.Value);
            }

            return policyBuilder.Build();
        }

        return (await FallbackPolicyProvider.GetPolicyAsync(policyName))!;
    }

    public Task<Microsoft.AspNetCore.Authorization.AuthorizationPolicy> GetDefaultPolicyAsync()
    {
        var policyBuilder = new AuthorizationPolicyBuilder();
        policyBuilder.RequireAuthenticatedUser(); // Например, требуется аутентификация для всех
        return Task.FromResult(policyBuilder.Build());
    }


    public Task<Microsoft.AspNetCore.Authorization.AuthorizationPolicy?> GetFallbackPolicyAsync()
    {
        return Task.FromResult<Microsoft.AspNetCore.Authorization.AuthorizationPolicy?>(null);
    }

}
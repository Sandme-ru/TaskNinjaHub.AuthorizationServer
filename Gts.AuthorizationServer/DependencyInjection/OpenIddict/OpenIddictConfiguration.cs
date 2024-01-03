using Gts.AuthorizationServer.Data;
using Gts.AuthorizationServer.Models.Workers;
using OpenIddict.Abstractions;

namespace Gts.AuthorizationServer.DependencyInjection.OpenIddict;

/// <summary>
/// Class OpenIddictConfiguration.
/// </summary>
public static class OpenIddictConfiguration
{
    /// <summary>
    /// Adds the o authentication authorization.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <returns>IServiceCollection.</returns>
    public static IServiceCollection AddOAuthAuthorization(this IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(options => {
                options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.DisableAccessTokenEncryption();
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetLogoutEndpointUris("/connect/logout")
                    .SetTokenEndpointUris("/connect/token")
                    .SetUserinfoEndpointUris("/connect/userinfo");
                options.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile, OpenIddictConstants.Scopes.Roles);
                options.AllowAuthorizationCodeFlow();
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                options.AddDevelopmentEncryptionCertificate();
                options.AddDevelopmentSigningCertificate();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableLogoutEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserinfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        services.AddHostedService<OpenIddictWorker>();
        return services;
    }
}
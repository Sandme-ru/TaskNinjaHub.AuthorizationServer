using Gts.AuthorizationServer.Context;
using OpenIddict.Abstractions;

namespace Gts.AuthorizationServer.Models.Workers;

public class OpenIddictWorker : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public OpenIddictWorker(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var client = await manager.FindByClientIdAsync("TaskNinjaHub");
        if (client != null)
            await manager.DeleteAsync(client);
        
        if (await manager.FindByClientIdAsync("TaskNinjaHub") == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "TaskNinjaHub",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3655",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = "TaskNinjaHub",
                RedirectUris =
                {
                    new Uri("https://localhost:7063"),
                    new Uri("https://localhost:7063/signin-oidc"),
                    new Uri("https://sandme.ru/task-ninja-hub"),
                    new Uri("https://sandme.ru/task-ninja-hub/signin-oidc"),
                    new Uri("https://sandme.ru"),
                    new Uri("https://sandme.ru/signin-oidc"),
                    new Uri("http://127.0.0.1/TaskNinjaHub.Desktop"),
                    new Uri("taskninjahub.mobile://authentication/login-callback"),
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:7063/signout-callback-oidc"),
                    new Uri("https://sandme.ru/signout-callback-oidc"),
                    new Uri("taskninjahub.mobile://authentication/logout-callback"),
                },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Logout,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

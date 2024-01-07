using Gts.AuthorizationServer.Context;
using OpenIddict.Abstractions;

namespace Gts.AuthorizationServer.Models.Workers;

/// <summary>
/// Class OpenIddictWorker.
/// Implements the <see cref="Microsoft.Extensions.Hosting.IHostedService" />
/// </summary>
/// <seealso cref="Microsoft.Extensions.Hosting.IHostedService" />
public class OpenIddictWorker : IHostedService
{
    /// <summary>
    /// The service provider
    /// </summary>
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="OpenIddictWorker"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    public OpenIddictWorker(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;

    /// <summary>
    /// Start as an asynchronous operation.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
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
                    new Uri("https://sandme.ru/task-ninja-hub"),
                    new Uri("https://localhost:7063/signin-oidc"),
                    new Uri("https://sandme.ru/task-ninja-hub/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:7063/signout-callback-oidc"),
                    new Uri("https://sandme.ru/task-ninja-hub/signout-callback-oidc")
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

    /// <summary>
    /// Triggered when the application host is performing a graceful shutdown.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the shutdown process should no longer be graceful.</param>
    /// <returns>Task.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
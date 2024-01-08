using Gts.AuthorizationServer.Context;
using Gts.AuthorizationServer.Data;
using Gts.AuthorizationServer.Data.AuthorizationPolicy;
using Gts.AuthorizationServer.DependencyInjection.OpenIddict;
using Gts.AuthorizationServer.Models.Users;
using Gts.AuthorizationServer.Services.Store.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NLog;
using NLog.Web;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

var builder = WebApplication.CreateBuilder(args);

#region LOGGING

builder.Host.ConfigureLogging(logging =>
{
    _ = logging.ClearProviders();
    _ = logging.SetMinimumLevel(LogLevel.Information);
}).UseNLog();

var logger = LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");

#endregion

try
{
    #region DBCONTEXT

    #if (DEBUG)

    const string defaultConnection = "DefaultConnection";

    #elif (RELEASE)

    const string defaultConnection = "ReleaseConnection";

    #endif
    builder.Services.AddScoped<IApplicationDbContext>(provider => provider.GetRequiredService<ApplicationDbContext>());
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString(defaultConnection) ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found."));
        options.UseOpenIddict();
    });

#endregion

    #region AUTHENTICATION

    builder.Services.AddOAuthAuthorization();

    builder.Services.AddAuthentication()
        .AddCookie("Legacy", options => { options.LoginPath = new PathString("/Legacy/Login"); });

    builder.Services.AddDatabaseDeveloperPageExceptionFilter();

    builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
        {
            options.User.AllowedUserNameCharacters =
                "‡·‚„‰Â∏ÊÁËÈÍÎÏÌÓÔÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ¿¡¬√ƒ≈®∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequiredLength = 8;
            options.Password.RequireUppercase = false;
            options.Lockout.AllowedForNewUsers = true;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
            options.Lockout.MaxFailedAccessAttempts = 10;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders()
        .AddDefaultUI();

    #endregion

    #region POLICY

    builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicAuthorizationPolicyProvider>();
    builder.Services.AddSingleton<IAuthorizationPolicyProviderService, AuthorizationPolicyProviderService>();
    builder.Services.AddSingleton<IUserProvider, UserProvider>();

    #endregion

    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "Keys")));

    builder.Services.AddControllersWithViews();
    builder.Services.AddRazorPages();
    builder.Services.AddSwaggerGen();

    builder.Services.Configure<OpenIddictServerAspNetCoreBuilder>(options =>
    {
        options.DisableTransportSecurityRequirement();
    });

    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders =
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    });

    builder.Services.AddSingleton<IClaimStore, ClaimStore>();

    var app = builder.Build();

    var forwardedHeaderOptions = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    };

    forwardedHeaderOptions.KnownNetworks.Clear();
    forwardedHeaderOptions.KnownProxies.Clear();

    if (app.Environment.IsDevelopment())
    {
        app.UseMigrationsEndPoint();
        app.UseSwagger();
        app.UseSwaggerUI();
        app.UseForwardedHeaders(forwardedHeaderOptions);
    }
    else
    {
        app.UseExceptionHandler("/Error");
        app.UseForwardedHeaders(forwardedHeaderOptions);
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    using (var serviceScope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateScope())
    {
        var dbContext = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        dbContext.MigrateDatabase();
    }

    app.UseRouting();

    app.UseCors();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
        endpoints.MapDefaultControllerRoute();
        endpoints.MapRazorPages();
        endpoints.MapGet("/", context =>
        {
            context.Response.Redirect("/account/login");
            return Task.CompletedTask;
        });
    });

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    LogManager.Shutdown();
}
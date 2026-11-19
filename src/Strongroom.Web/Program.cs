using Strongroom.Core;
using Strongroom.Core.Storage;
using Strongroom.Web.Security;

const string SessionCookie = "sr_session";
var idleTimeout = TimeSpan.FromMinutes(5);

var builder = WebApplication.CreateBuilder(args);

// When started by the Windows Service Control Manager this hosts the app as a service
// (and fixes the content root to the install folder); when run from a console it does nothing.
builder.Host.UseWindowsService(options => options.ServiceName = "Strongroom");

var dbPath = builder.Configuration["Strongroom:DatabasePath"];
if (string.IsNullOrWhiteSpace(dbPath))
{
    // Default: <repo root>\data\strongroom.db (found by walking up to Strongroom.slnx);
    // if the app runs outside the repo, fall back to the user's local app data.
    var root = new DirectoryInfo(builder.Environment.ContentRootPath);
    while (root is not null && !root.GetFiles("Strongroom.slnx").Any()) root = root.Parent;
    dbPath = root is not null
        ? Path.Combine(root.FullName, "data", "strongroom.db")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Strongroom", "strongroom.db");
}

dbPath = Path.GetFullPath(dbPath);
if (Directory.Exists(dbPath) || dbPath.EndsWith(Path.DirectorySeparatorChar) || dbPath.EndsWith(Path.AltDirectorySeparatorChar))
{
    Console.Error.WriteLine("Strongroom cannot start: Strongroom:DatabasePath must be a file path, not a folder.");
    Console.Error.WriteLine($"  Current value: {dbPath}");
    Console.Error.WriteLine($"  Example:       {Path.Combine(dbPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), "strongroom.db")}");
    Console.Error.WriteLine("  (Set it in appsettings.json, or leave it empty to use the default.)");
    Environment.Exit(1);
}

VaultStore store;
try
{
    store = new VaultStore(dbPath);
}
catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"Strongroom cannot start: unable to open the vault database at {dbPath}");
    Console.Error.WriteLine($"  {ex.Message}");
    Console.Error.WriteLine("  Check that the folder exists and is writable, and that no other program has the file locked.");
    Environment.Exit(1);
    return; // unreachable; satisfies definite assignment
}

builder.Services.AddSingleton(store);
builder.Services.AddSingleton(sp => new VaultService(sp.GetRequiredService<VaultStore>()));
builder.Services.AddSingleton(new SessionStore(idleTimeout));
builder.Services.AddSingleton<LoginThrottle>();

var app = builder.Build();

// ---- Hardening middleware -------------------------------------------------
app.Use(async (ctx, next) =>
{
    // Blocks DNS-rebinding: only answer requests addressed to this machine.
    var host = ctx.Request.Host.Host;
    if (host is not ("localhost" or "127.0.0.1" or "[::1]" or "::1"))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    ctx.Response.Headers.ContentSecurityPolicy =
        "default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";

    if (ctx.Request.Path.StartsWithSegments("/api"))
    {
        ctx.Response.Headers.CacheControl = "no-store";

        // CSRF: browsers can't add a custom header cross-site without a CORS preflight (which we never allow).
        var safe = HttpMethods.IsGet(ctx.Request.Method);
        if (!safe && ctx.Request.Headers["X-Strongroom"] != "1")
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

// ---- Helpers --------------------------------------------------------------
void SetSessionCookie(HttpContext ctx, string token) =>
    ctx.Response.Cookies.Append(SessionCookie, token, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        IsEssential = true,
        Path = "/",
    });

static string? Validate(CredentialData d)
{
    if (string.IsNullOrWhiteSpace(d.Name)) return "Name is required.";
    if (d.Name.Length > 200 || d.Url?.Length > 500 || d.Username?.Length > 300 ||
        d.Password?.Length > 1000 || d.Category?.Length > 100 || d.Notes?.Length > 5000)
        return "One of the fields is too long.";
    return null;
}

static CredentialData Clean(CredentialData d) => new(
    d.Name.Trim(), d.Url?.Trim() ?? "", d.Username?.Trim() ?? "",
    d.Password ?? "", string.IsNullOrWhiteSpace(d.Category) ? "Other" : d.Category.Trim(), d.Notes?.Trim() ?? "");

// ---- Auth endpoints ---------------------------------------------------------
var auth = app.MapGroup("/api");

auth.MapGet("/status", (HttpContext ctx, SessionStore sessions) =>
{
    var vault = sessions.Get(ctx.Request.Cookies[SessionCookie]);
    return Results.Ok(new { unlocked = vault is not null, username = vault?.Username });
});

auth.MapPost("/register", (RegisterRequest req, HttpContext ctx, VaultService vaults, SessionStore sessions) =>
{
    var result = vaults.Register(req.Username, req.Password);
    switch (result)
    {
        case RegisterResult.InvalidUsername:
            return Results.BadRequest(new { error = $"Username must be {VaultService.MinUsernameLength}-{VaultService.MaxUsernameLength} characters." });
        case RegisterResult.WeakPassword:
            return Results.BadRequest(new { error = $"Master password must be at least {VaultService.MinPasswordLength} characters." });
        case RegisterResult.UsernameTaken:
            return Results.Conflict(new { error = "That username is already taken." });
    }

    var vault = vaults.Unlock(req.Username, req.Password)!;
    SetSessionCookie(ctx, sessions.Create(vault));
    return Results.Ok(new { username = vault.Username });
});

auth.MapPost("/login", (LoginRequest req, HttpContext ctx, VaultService vaults, SessionStore sessions, LoginThrottle throttle) =>
{
    var name = req.Username?.Trim() ?? "";
    var wait = throttle.SecondsLocked(name);
    if (wait > 0)
        return Results.Json(new { error = $"Too many attempts. Try again in {wait}s." }, statusCode: StatusCodes.Status429TooManyRequests);

    var vault = vaults.Unlock(name, req.Password);
    if (vault is null)
    {
        throttle.RecordFailure(name);
        return Results.Json(new { error = "Incorrect username or master password." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    throttle.RecordSuccess(name);
    SetSessionCookie(ctx, sessions.Create(vault));
    return Results.Ok(new { username = vault.Username });
});

auth.MapPost("/logout", (HttpContext ctx, SessionStore sessions) =>
{
    sessions.Remove(ctx.Request.Cookies[SessionCookie]);
    ctx.Response.Cookies.Delete(SessionCookie);
    return Results.NoContent();
});

// ---- Endpoints that require an unlocked session -------------------------------------
async ValueTask<object?> RequireSession(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
{
    var ctx = invocation.HttpContext;
    var vault = ctx.RequestServices.GetRequiredService<SessionStore>().Get(ctx.Request.Cookies[SessionCookie]);
    if (vault is null) return Results.Json(new { error = "Locked." }, statusCode: StatusCodes.Status401Unauthorized);
    ctx.Items["vault"] = vault;
    return await next(invocation);
}

var account = app.MapGroup("/api/account");
account.AddEndpointFilter(RequireSession);

account.MapPost("/change-password", (ChangePasswordRequest req, HttpContext ctx, VaultService vaults, SessionStore sessions, LoginThrottle throttle) =>
{
    var vault = (UnlockedVault)ctx.Items["vault"]!;

    // Same guessing protection as login: a stolen session must not be able to brute-force the current password.
    var wait = throttle.SecondsLocked(vault.Username);
    if (wait > 0)
        return Results.Json(new { error = $"Too many attempts. Try again in {wait}s." }, statusCode: StatusCodes.Status429TooManyRequests);

    switch (vaults.ChangeMasterPassword(vault, req.CurrentPassword ?? "", req.NewPassword ?? ""))
    {
        case ChangePasswordResult.WrongCurrentPassword:
            throttle.RecordFailure(vault.Username);
            return Results.Json(new { error = "The current master password is incorrect." }, statusCode: StatusCodes.Status403Forbidden);
        case ChangePasswordResult.WeakPassword:
            return Results.BadRequest(new { error = $"The new master password must be at least {VaultService.MinPasswordLength} characters." });
        case ChangePasswordResult.SameAsCurrent:
            return Results.BadRequest(new { error = "The new master password must be different from the current one." });
    }

    throttle.RecordSuccess(vault.Username);
    sessions.RemoveOthers(vault.UserId, ctx.Request.Cookies[SessionCookie]); // lock any other open sessions
    return Results.NoContent();
});

var creds = app.MapGroup("/api/credentials");
creds.AddEndpointFilter(RequireSession);

creds.MapGet("/", (HttpContext ctx) => Results.Ok(((UnlockedVault)ctx.Items["vault"]!).List()));

creds.MapPost("/", (CredentialData data, HttpContext ctx) =>
{
    if (Validate(data) is { } error) return Results.BadRequest(new { error });
    return Results.Ok(((UnlockedVault)ctx.Items["vault"]!).Add(Clean(data)));
});

creds.MapPut("/{id:guid}", (Guid id, CredentialData data, HttpContext ctx) =>
{
    if (Validate(data) is { } error) return Results.BadRequest(new { error });
    return ((UnlockedVault)ctx.Items["vault"]!).Update(id, Clean(data)) is { } updated
        ? Results.Ok(updated)
        : Results.NotFound();
});

creds.MapDelete("/{id:guid}", (Guid id, HttpContext ctx) =>
    ((UnlockedVault)ctx.Items["vault"]!).Delete(id) ? Results.NoContent() : Results.NotFound());

app.Run();

record RegisterRequest(string Username, string Password);
record LoginRequest(string Username, string Password);
record ChangePasswordRequest(string CurrentPassword, string NewPassword);

// Lets integration tests reference the entry point.
public partial class Program;

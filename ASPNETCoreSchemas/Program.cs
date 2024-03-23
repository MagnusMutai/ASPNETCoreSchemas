using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", o => { })
    .AddCookie("local")
    .AddCookie("patreon-cookie")
    .AddOAuth("external-patreon", o =>
    {
        o.SignInScheme = "patreon-cookie";

        o.ClientId = "id";
        o.ClientSecret = "secret";

        o.AuthorizationEndpoint = "https://oauth.wiremockapi.cloud/oauth/authorize";
        o.TokenEndpoint = "https://oauth.wiremockapi.cloud/oauth/token";
        o.UserInformationEndpoint = "https://oauth.wiremockapi.cloud/userinfo";

        o.CallbackPath = "/cb-patreon";

        o.Scope.Add("profile");
        o.SaveTokens = true;
    });
builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("customer", p =>
    {
        p.AddAuthenticationSchemes("patreon-cookie", "local", "visitor")
            .RequireAuthenticatedUser();
    });
    b.AddPolicy("user", p =>
    {
        p.AddAuthenticationSchemes("local")
            .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", ctx => Task.FromResult("Hello World!")).RequireAuthorization("customer");

app.MapGet("/login-local", async (ctx) =>
{
var claims = new List<Claim>();
claims.Add(new Claim("usr", "anton"));
var identity = new ClaimsIdentity(claims, "local");
var user = new ClaimsPrincipal(identity);

await ctx.SignInAsync("local", user);
});

app.MapGet("/login-patreon", async (ctx) => await ctx.ChallengeAsync("external-patreon", new AuthenticationProperties()
{
    RedirectUri = "/"
})).RequireAuthorization("user");

app.Run();

public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "anton"));
        var identity = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identity);

        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));

    }
}

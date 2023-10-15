using System.Collections.Immutable;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using System.Web;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        //private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly AuthorizationService _authorizationService;
        private readonly RabbitMQPublisher _rabbitMQPublisher;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            AuthorizationService authorizationService,
            RabbitMQPublisher rabbitMQPublisher)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _authorizationService = authorizationService;
            _rabbitMQPublisher = rabbitMQPublisher;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            //// Retrieve the profile of the logged in user.
            //var user = await _userManager.GetUserAsync(result.Principal) ??
            //    throw new InvalidOperationException("The user details cannot be retrieved.");
            
            var parameters = _authorizationService.ParseParams(HttpContext, new List<string> { Parameters.Prompt });

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var isAuthenticated = _authorizationService.IsAuthenticated(result, request);

            if (!isAuthenticated)
            {
                return Challenge(
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = _authorizationService.BuildRedirectUrl(HttpContext.Request, parameters)
                    },
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme
                );
            }

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                              throw new InvalidOperationException("Details regarding to the calling client application cannot be found.");

            var consentType = await _applicationManager.GetConsentTypeAsync(application);

            if (consentType != ConsentTypes.Explicit)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Only clients with explicit consent type are allowed."
                    }));
            }

            var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

            // If the resource owner hasn't granted access to the resource owner's data, or for any reason we should re-ask for access permission
            if (consentClaim != Consts.GrantAccessValue)// || request.HasPrompt(Prompts.Consent))
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                var returnUrl = HttpUtility.UrlEncode(_authorizationService.BuildRedirectUrl(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?ReturnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }


            var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

            // Token issuing
            // Create the claims-based indentity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Add the claims that will be persisted in the tokens. Assuming all scopes accessible here
            identity.SetClaim(Claims.Subject, userId/*_userManager.GetUserIdAsync(user)*/)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            // Send to MonitoringService
            var userInfo = new { Email = userId, Code = User.GetClaim(Claims.AccessTokenHash)};
            var userInfoJson = Newtonsoft.Json.JsonConvert.SerializeObject(userInfo);
            _rabbitMQPublisher.Publish(userInfoJson, "user_signup_queue");

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");

            var result =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        //[Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        //[HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
        //public async Task<IActionResult> Userinfo()
        //{
        //    if (User.GetClaim(Claims.Subject) != Consts.Email)
        //    {
        //        return Challenge(
        //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        //            properties: new AuthenticationProperties(new Dictionary<string, string?>
        //            {
        //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
        //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
        //                    "The specified access token is bound to an account that no longer exists."
        //            }));
        //    }

        //    var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        //    {
        //        // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
        //        [Claims.Subject] = Consts.Email
        //    };

        //    if (User.HasScope(Scopes.Email))
        //    {
        //        claims[Claims.Email] = Consts.Email;
        //    }

        //    return Ok(claims);
        //}

        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }
    }
}

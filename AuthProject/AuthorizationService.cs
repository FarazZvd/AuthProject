using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Linq;
using System.Security.Claims;

namespace AuthorizationServer
{
    public class AuthorizationService
    {
        public IDictionary<string, StringValues> ParseParams(HttpContext httpContext, List<string>? excluding = null)
    {
        excluding ??= new List<string>();

        var parameters = httpContext.Request.HasFormContentType ?
                httpContext.Request.Form.Where(v => !excluding.Contains(v.Key)).ToDictionary(v => v.Key, v => v.Value) :
                httpContext.Request.Query.Where(v => !excluding.Contains(v.Key)).ToDictionary(v => v.Key, v => v.Value);

        return parameters;
    }

        public bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request)
        {
            if (!authenticateResult.Succeeded)
            {
                return false;
            }

            if (request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeInSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);
                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeInSeconds;

                if (expired)
                {
                    return false;
                }
            }

            // RabbitMQ -> if every sign-in is intended to be logged
            return true;
        }

        public string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> oAuthParameters)
        {
            var url = request.PathBase + request.Path + QueryString.Create(oAuthParameters);
            return url;
        }

        public static List<string> GetDestinations(ClaimsIdentity identity, Claim claim)
        {
            var destinations = new List<string>();

            if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
            {
                destinations.Add(OpenIddictConstants.Destinations.AccessToken);

                //if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
                //{
                //    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                //}
            }

            return destinations;
        }
    }
}
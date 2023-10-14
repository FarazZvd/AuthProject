using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Linq;
using System.Security.Claims;

namespace AuthProject
{
    public class AuthorizationService
    {
        public IDictionary<string, StringValues> ParseParams(HttpContext httpContext)
        {
            //Parameter exclusion could be handled here, but not necessaey now!
            var parameters = httpContext.Request.HasFormContentType ?
                httpContext.Request.Form.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) :
                httpContext.Request.Query.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

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

            // RabbitMQ
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

                if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
                {
                    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                }
            }

            return destinations;
        }
    }
}
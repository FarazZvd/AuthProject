using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ResourceServer.Controllers
{
    [ApiController]
    [Authorize]//(CookieAuthenticationDefaults.AuthenticationScheme)]
    [Route("resources")]
    public class ResourceController : ControllerBase
    {
         [HttpGet]
        public IActionResult Get()
        {
            var user = HttpContext.User?.Identity?.Name;

            return Ok($"Access granted to: {user}'s resources");
        }
    }
}
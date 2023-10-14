using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace AuthProject.Pages
{
    public class AuthenticateModel : PageModel
    {
        public string Email { get; set; }
        public string Password { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public string AuthStatus { get; set; } = "";

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string email, string password)
        {
            // Authenticate user
            if (email != Consts.Email || password != Consts.Password)
            {
                AuthStatus = "Not authenticated!";
                return Page();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, email)
            };

            var principal = new ClaimsPrincipal(
            new List<ClaimsIdentity> 
            {
                new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)
            });

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            
            if(!String.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }

            AuthStatus = "Authenticated";

            return Page();
        }
    }
}

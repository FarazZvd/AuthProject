using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace AuthProject.Pages
{
    [Authorize(CookieAuthenticationDefaults.AuthenticationScheme)]
    public class ConfirmModel : PageModel
    {
        [BindProperty]
        public string ReturnUrl { get; set; }
        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string grant)
        {
            if (grant != Consts.GrantAccessValue)
            {
                return Forbid();
            }

            var consentClaim = User.GetClaim(Consts.ConsentNaming);

            if (string.IsNullOrEmpty(consentClaim)) // New User => Sign up event => send via RabbitMQ to be loggged on console
            {
                User.SetClaim(Consts.ConsentNaming, grant);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);
                
                // log consentClaim

            }
            
            return Redirect(ReturnUrl);
        }
    }
}

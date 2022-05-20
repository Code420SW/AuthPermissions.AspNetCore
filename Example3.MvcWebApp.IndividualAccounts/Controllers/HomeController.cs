using Example3.MvcWebApp.IndividualAccounts.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Threading.Tasks;
using Example3.InvoiceCode.Dtos;
using Example3.InvoiceCode.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index(string message)
        {
            ViewBag.Message = message;

            // Get the user's tenant name
            // If it is null, go to te AppSummary view
            if (AddTenantNameClaim.GetTenantNameFromUser(User) == null)
                return View(new AppSummary());

            // Otherwise, invoke the Index action in the Invoice controller
            return RedirectToAction("Index", "Invoice");
        }

        public IActionResult CreateTenant()
        {
            // If the user is logged in, invoke the Index action with a message
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", new { message = "You can't create a new tenant because you are all ready logged in." });

            // Otherwise, return the CreateTenant view where user can sign up
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateTenant(CreateTenantDto data,
                                                      [FromServices] IUserRegisterInviteService userRegisterInvite,
                                                      [FromServices] SignInManager<IdentityUser> signInManager)
        {
            // This does three things (with lots of checks)
            // - Adds the new user to the the individual account
            // - Adds an AuthUser for this person
            // - Creates the tenant with the correct tenant roles
            // NOTE: On return you MUST sign in the user using the email and password they provided via the individual accounts signInManager
            //
            // Afer successful completion, the new/existing IdentityUser record is returned in status.Result
            var status = await userRegisterInvite.AddUserAndNewTenantAsync(data);
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            //User has been successfully registered so now we need to log them in
            // Yup, time to authenticate the user
            await signInManager.SignInAsync(status.Result, isPersistent: false);

            return RedirectToAction(nameof(Index),
                new { message = status.Message });
        }

        [AllowAnonymous]
        public ActionResult AcceptInvite(string verify)
        {
            return View(new AcceptInviteDto { Verify = verify });
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AcceptInvite(AcceptInviteDto data,
                                                     [FromServices] IUserRegisterInviteService userRegisterInvite,
                                                     [FromServices] SignInManager<IdentityUser> signInManager)
        {

            //The data.Verify property is an encryped string send to the invited user and is the verify parameter on the
            // URL the user goes to to accept the invivation. The string contains the tenant Id and the email address
            // to which the invite was sent.
            //
            // Create the IdentityUser record if needed. Create a new AuthUser record (exusting AuthUser can't we associated with more than one tenant)
            // The new/existing IdentityUser record is return in status.Result
            var status = await userRegisterInvite.AcceptUserJoiningATenantAsync(data.Email, data.Password, data.Verify);
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            //User has been successfully registered so now we need to log them in
            await signInManager.SignInAsync(status.Result, isPersistent: false);

            return RedirectToAction(nameof(Index),
                new { message = status.Message });
        }

        public ActionResult ErrorDisplay(string errorMessage)
        {
            return View((object)errorMessage);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

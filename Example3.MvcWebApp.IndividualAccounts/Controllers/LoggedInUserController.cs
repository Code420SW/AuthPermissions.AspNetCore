using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.PermissionsCode;
using ExamplesCommonCode.CommonAdmin;
using Microsoft.AspNetCore.Mvc;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class LoggedInUserController : Controller
    {
        public IActionResult Index()
        {
            return View(User);
        }

        public async Task<IActionResult> AuthUserInfo([FromServices]IAuthUsersAdminService service)
        {
            // If the user is logged in...
            if (User.Identity?.IsAuthenticated == true)
            {
                // Extract the user Id from the User record
                var userId = User.GetUserIdFromUser();

                // Try to find the user's AuthUser record.
                // Returned in status.Result
                var status = await service.FindAuthUserByUserIdAsync(userId);

                if (status.HasErrors)
                    return RedirectToAction("ErrorDisplay", "AuthUsers",
                        new { errorMessage = status.GetAllErrors() });

                return View(AuthUserDisplay.DisplayUserInfo(status.Result));
            }

            // Null record if the user is not logged in
            return View((AuthUserDisplay)null);
        }

        public IActionResult UserPermissions([FromServices] IUsersPermissionsService service)
        {
            // This returns all the permissions in the provided ClaimsPrincipal (or null if no user or permission claim)
            return View(service.PermissionsFromUser(HttpContext.User));
        }
    }
}

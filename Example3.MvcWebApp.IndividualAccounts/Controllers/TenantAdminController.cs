using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.AspNetCore;
using AuthPermissions.BaseCode.CommonCode;
using Example3.InvoiceCode.Services;
using Example3.MvcWebApp.IndividualAccounts.Models;
using Example3.MvcWebApp.IndividualAccounts.PermissionsCode;
using ExamplesCommonCode.CommonAdmin;
using Microsoft.EntityFrameworkCore;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class TenantAdminController : Controller
    {
        private readonly IAuthUsersAdminService _authUsersAdmin;

        public TenantAdminController(IAuthUsersAdminService authUsersAdmin)
        {
            _authUsersAdmin = authUsersAdmin;
        }


        [HasPermission(Example3Permissions.UserRead)]
        public async Task<IActionResult> Index(string message)
        {
            // This returns the AuthP DataKey. Can be null if AuthP user has no user,
            // user not a tenants, or tenants are not configured
            var dataKey = User.GetAuthDataKeyFromUser();

            // This returns a IQueryable of AuthUser, with optional filtering by dataKey (useful for tenant admin)
            var userQuery = _authUsersAdmin.QueryAuthUsers(dataKey);

            // First sort the list of AuthUser records by email
            // and then build a list of AuthUserDisplay records
            var usersToShow = await AuthUserDisplay.TurnIntoDisplayFormat(userQuery.OrderBy(x => x.Email)).ToListAsync();

            ViewBag.Message = message;

            return View(usersToShow);
        }


        public async Task<ActionResult> EditRoles(string userId)
        {
            // Return (in status,Result) a prepopulated SetupManualUserChange record for the passed userId.
            var status = await SetupManualUserChange.PrepareForUpdateAsync(userId, _authUsersAdmin);

            // Handle errors
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            return View(status.Result);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EditRoles(SetupManualUserChange change)
        {
            // This update an existing AuthUser. This method is designed so you only have to provide data for the parts you want to update,
            // i.e. if a parameter is null, then it keeps the original setting. The only odd one out is the tenantName,
            // where you have to provide the <see cref="CommonConstants.EmptyTenantName"/> value to remove the tenant.
            var status = await _authUsersAdmin.UpdateUserAsync(change.UserId,
                roleNames: change.RoleNames);

            // Handle errors
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            return RedirectToAction(nameof(Index), new { message = status.Message });
        }


        [HasPermission(Example3Permissions.InviteUsers)]
        public async Task<ActionResult> InviteUser()
        {
            // Finds the AuthUser record for the current user.
            // Finds a AuthUser via its UserId. Returns a status with an error if not found
            // The AuthUser record is returned in the Result parameter of the returned status
            var currentUser = (await _authUsersAdmin.FindAuthUserByUserIdAsync(User.GetUserIdFromUser()))
                .Result;

            // Only the tenant name (if any) is passed to the view.
            return View((object) currentUser?.UserTenant?.TenantFullName);
        }


        [HasPermission(Example3Permissions.InviteUsers)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> InviteUser([FromServices] IUserRegisterInviteService userRegisterInvite, string email)
        {
            // Finds the AuthUser record for the current user.
            // Finds a AuthUser via its UserId. Returns a status with an error if not found
            // The AuthUser record is returned in the Result parameter of the returned status
            var currentUser = (await _authUsersAdmin.FindAuthUserByUserIdAsync(User.GetUserIdFromUser()))
                .Result;

            // If the AuthUser record for the current user is not found or the user does not have a tenant, error.
            if (currentUser == null || currentUser.TenantId == null)
                return RedirectToAction(nameof(ErrorDisplay), new { errorMessage = "must be logged in and have a tenant" });

            // This creates a an encrypted string containing the tenantId and the user's email
            /// so that you can confirm the user is valid
            var verify = userRegisterInvite.InviteUserToJoinTenantAsync((int)currentUser.TenantId, email);

            // Construct the absolute URL to the Home Controller's AcceptInvite action
            var inviteUrl = AbsoluteAction(Url, nameof(HomeController.AcceptInvite), "Home",  new { verify });

            // Go to the view showing the invitation URL
            return View("InviteUserUrl", new InviteUserDto(email, currentUser.UserTenant.TenantFullName, inviteUrl));
        }


        public ActionResult ErrorDisplay(string errorMessage)
        {
            return View((object)errorMessage);
        }


        //-------------------------------------------------------

        //Thanks to https://stackoverflow.com/questions/30755827/getting-absolute-urls-using-asp-net-core
        public string AbsoluteAction(IUrlHelper url,
            string actionName,
            string controllerName,
            object routeValues = null)
        {
            string scheme = HttpContext.Request.Scheme;
            return url.Action(actionName, controllerName, routeValues, scheme);
        }
    }
}

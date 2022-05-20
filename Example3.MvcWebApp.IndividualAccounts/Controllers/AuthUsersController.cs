using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.BaseCode.CommonCode;
using Example3.MvcWebApp.IndividualAccounts.Models;
using ExamplesCommonCode.CommonAdmin;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class AuthUsersController : Controller
    {
        private readonly IAuthUsersAdminService _authUsersAdmin;

        public AuthUsersController(IAuthUsersAdminService authUsersAdmin)
        {
            _authUsersAdmin = authUsersAdmin;
        }

        // List users filtered by authUser tenant
        //[HasPermission(Example4Permissions.UserRead)]
        public async Task<ActionResult> Index(string message)
        {
            // This returns the AuthP DataKey. Can be null if AuthP user has no user, user not a tenants, or tenants are not configured
            var authDataKey = User.GetAuthDataKeyFromUser();

            // This returns a IQueryable of AuthUser, with optional filtering by dataKey (useful for tenant admin)
            // Okay if authDataKey is null--will return all AuthUsers from the db
            var userQuery = _authUsersAdmin.QueryAuthUsers(authDataKey);

            // Function located in ExamplesCommonCode.CommonAdmin as static IQueryable<AuthUserDisplay> TurnIntoDisplayFormat(IQueryable<AuthUser> inQuery)
            // Converts the list of AuthUser to list of AuthUserDisplay
            var usersToShow = await AuthUserDisplay.TurnIntoDisplayFormat(userQuery.OrderBy(x => x.Email)).ToListAsync();

            ViewBag.Message = message;

            return View(usersToShow);
        }

        public async Task<ActionResult> Edit(string userId)
        {
            // Function located in ExamplesCommonCode.CommonAdmin as
            // public static async Task<IStatusGeneric<SetupManualUserChange>> PrepareForUpdateAsync(string userId,IAuthUsersAdminService authUsersAdmin)
            // Get the AuthUser info from the db and returns it in the status.Result property
            var status = await SetupManualUserChange.PrepareForUpdateAsync(userId,_authUsersAdmin);

            // Any errors are redirected to the Erros view
            if(status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Otherwise, return the SetupManualUserChange record to the view
            return View(status.Result);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(SetupManualUserChange change)
        {
            // Try to update the AuthUser record and capture status
            var status = await _authUsersAdmin.UpdateUserAsync(change.UserId,
                change.Email, change.UserName, change.RoleNames, change.TenantName);

            // Any errors are redirected to the Erros view
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Otherwise, redirect the Index view
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }

        public async Task<ActionResult> SyncUsers()
        {
            //This compares the users in the authentication provider against the user's in the AuthP's database.
            // It creates a list of all the changes (add, update, remove) than need to be applied to the AuthUsers.
            // This is shown to the admin user to check, and fill in the Roles/Tenant parts for new users
            var syncChanges = await _authUsersAdmin.SyncAndShowChangesAsync();

            return View(syncChanges);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]        
        //NOTE: the input be called "data" because we are using JavaScript to send that info back
        public async Task<ActionResult> SyncUsers(IEnumerable<SyncAuthUserWithChange> data)
        {
            // Apply the changes and capture results in status
            var status = await _authUsersAdmin.ApplySyncChangesAsync(data);

            // If any errors, redirect to the Errors view
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors()});

            // Otherwise, redirect to the Index view
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }

        // GET: AuthUsersController/Delete/5
        public async Task<ActionResult> Delete(string userId)
        {
            // Get the AuthUser record for the passed userId and capture results in sttus
            var status = await _authUsersAdmin.FindAuthUserByUserIdAsync(userId);

            // If any errors, redirect to the Errors view
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Otherwise, create an AuthUserDisplay record for the deleted user and return to the Delete view
            return View(AuthUserDisplay.DisplayUserInfo(status.Result));
        }

        // POST: AuthUsersController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(AuthIdAndChange input)
        {
            // This will delete the AuthUser with the given userId
            var status = await _authUsersAdmin.DeleteUserAsync(input.UserId);

            // If errors, redirect to Errors view
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Otherwise, redirect to the Index view
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }

        public ActionResult ErrorDisplay(string errorMessage)
        {
            return View((object) errorMessage);
        }
    }
}

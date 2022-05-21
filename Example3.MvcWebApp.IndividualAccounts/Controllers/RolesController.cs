using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.AspNetCore;
using AuthPermissions.BaseCode.CommonCode;
using Example3.MvcWebApp.IndividualAccounts.PermissionsCode;
using ExamplesCommonCode.CommonAdmin;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class RolesController : Controller
    {
        private readonly IAuthRolesAdminService _authRolesAdmin;

        public RolesController(IAuthRolesAdminService authRolesAdmin)
        {
            _authRolesAdmin = authRolesAdmin;
        }

        [HasPermission(Example3Permissions.RoleRead)]
        public async Task<IActionResult> Index(string message)
        {
            // Get the user Id from the User record
            var userId = User.GetUserIdFromUser();

            // Build a list of RoleToPermissionNamesDto records that are valid
            // for the tenant and then order the list.
            var permissionDisplay = await
                _authRolesAdmin.QueryRoleToPermissions(userId)
                    .OrderBy(x => x.RoleType)  
                    .ToListAsync();

            ViewBag.Message = message;

            return View(permissionDisplay);
        }


        [HasPermission(Example3Permissions.PermissionRead)]
        public IActionResult ListPermissions()
        {
            // This returns a list of permissions with the information from the Display attribute
            // NOTE: This should not be called by a user that has a tenant, but this isn't checked
            var permissionDisplay = _authRolesAdmin.GetPermissionDisplay(false);

            return View(permissionDisplay);
        }


        [HasPermission(Example3Permissions.RoleChange)]
        public async Task<IActionResult> Edit(string roleName)
        {
            // This returns the UserId from the current user
            var userId = User.GetUserIdFromUser();

            // This simply returns a IQueryable of the <see cref="RoleWithPermissionNamesDto"/>.
            // This contains all the properties in the <see cref="RoleToPermissions"/> class, plus a list of the Permissions names
            // This can be by a user linked to a tenant and it will display all the roles that tenant can use 
            //
            // Filter the list of RolleWithPermissionNamesDto to include only those with the passed roleName
            var role = await
                _authRolesAdmin.QueryRoleToPermissions(userId).SingleOrDefaultAsync(x => x.RoleName == roleName);

            // This returns a list of permissions with the information from the Display attribute
            // NOTE: This should not be called by a user that has a tenant, but this isn't checked
            var permissionsDisplay = _authRolesAdmin.GetPermissionDisplay(false);

            // This created a RoleCreateUpdateDto containing the role information
            // including a sub-list of permissions (in the PermissionsWithSelect property) containg
            // all permissions including and indication of which permissions are currently
            // associated with the role (in the PermissionsWithSelect.Selected property).
            return View(role == null ? null : RoleCreateUpdateDto.SetupForCreateUpdate(role.RoleName, role.Description, 
                role.PermissionNames, permissionsDisplay, role.RoleType));
        }


        [HasPermission(Example3Permissions.RoleChange)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(RoleCreateUpdateDto input)
        {
            // Takes the RoleCreateUpdateDto object (handed to the user via the Edit(string roleName) action)
            // containg the user edits and saves them to the db.
            //
            // This updates the role's permission names, and optionally its description
            // if the new permissions contain an advanced permission
            var status = await _authRolesAdmin
                .UpdateRoleToPermissionsAsync(input.RoleName, input.GetSelectedPermissionNames(), input.Description, input.RoleType);

            // Handle errors
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Go back to the Index page
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }


        [HasPermission(Example3Permissions.RoleChange)]
        public IActionResult Create()
        {
            // This returns a list of permissions with the information from the Display attribute
            // NOTE: This should not be called by a user that has a tenant, but this isn't checked
            var permissionsDisplay = _authRolesAdmin.GetPermissionDisplay(false);

            // This created a RoleCreateUpdateDto containing the role information
            // including a sub-list of permissions (in the PermissionsWithSelect property) containg
            // all permissions including and indication of which permissions are currently
            // associated with the role (in the PermissionsWithSelect.Selected property).
            return View(RoleCreateUpdateDto.SetupForCreateUpdate(null, null, null, permissionsDisplay));
        }


        [HasPermission(Example3Permissions.RoleChange)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(RoleCreateUpdateDto input)
        {
            // The GetSelectedPermissionNames method returns a list of the permission
            // names selected in passed RoleCreateUpdateDto.
            // CreateRoleToPermissionsAsync adds a new RoleToPermissions with the given description
            // and permissions defined by the names
            var status = await _authRolesAdmin
                .CreateRoleToPermissionsAsync(input.RoleName, input.GetSelectedPermissionNames(), input.Description, input.RoleType);

            // If errors, go to the Error page
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Go back to the Index page
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }


        public ActionResult ErrorDisplay(string errorMessage)
        {
            return View((object)errorMessage);
        }


        [HasPermission(Example3Permissions.RoleChange)]
        public async Task<IActionResult> Delete(string roleName)
        {
            // This is the multi-tenant delete confirm where you need to display what uses and tenants are using a Role
            return View(await MultiTenantRoleDeleteConfirmDto.FormRoleDeleteConfirmDtoAsync(roleName, _authRolesAdmin));
        }


        [HasPermission(Example3Permissions.RoleChange)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(RoleDeleteConfirmDto input)
        {
            // This deletes a Role. If that Role is already assigned to AuthP users you must set the removeFromUsers to true
            // otherwise you will get an error.
            // In the view, the user confirmed deletion by typing the role name in an input.
            // The second parameter compares this input value to the role name to set the removeFromUsers flag.
            var status = await _authRolesAdmin.DeleteRoleAsync(input.RoleName, input.ConfirmDelete?.Trim() == input.RoleName);
            
            // Handle errors
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Go to the Index page
            return RedirectToAction(nameof(Index), new { message = status.Message });
        }
    }
}

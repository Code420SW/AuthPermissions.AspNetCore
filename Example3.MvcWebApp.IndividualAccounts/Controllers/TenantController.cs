using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.AspNetCore;
using AuthPermissions.AspNetCore.AccessTenantData;
using AuthPermissions.BaseCode.CommonCode;
using Example3.MvcWebApp.IndividualAccounts.Models;
using Example3.MvcWebApp.IndividualAccounts.PermissionsCode;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class TenantController : Controller
    {
        private readonly IAuthTenantAdminService _authTenantAdmin;

        public TenantController(IAuthTenantAdminService authTenantAdmin)
        {
            _authTenantAdmin = authTenantAdmin;
        }


        [HasPermission(Example3Permissions.TenantList)]
        public async Task<IActionResult> Index(string message)
        {
            // QueryTenants simply returns a IQueryable of Tenants
            // TurnIntoDisplayFormat returns a list of SinglrLevelTenantDto records
            // And then sort by tenant name and convert to a list
            var tenantNames = await SingleLevelTenantDto.TurnIntoDisplayFormat( _authTenantAdmin.QueryTenants())
                .OrderBy(x => x.TenantName)
                .ToListAsync();

            ViewBag.Message = message;

            return View(tenantNames);
        }


        [HasPermission(Example3Permissions.TenantCreate)]
        public async Task<IActionResult> Create()
        {
            // Construct a SingleLevelTenantDto record that is blank except for the AllPossibleRoleNames parameter
            // GetRoleNamesForTenantsAsync returns a list of all the RoleNames that can be applied to a Tenant
            return View(new SingleLevelTenantDto { AllPossibleRoleNames = await _authTenantAdmin.GetRoleNamesForTenantsAsync() });
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [HasPermission(Example3Permissions.TenantCreate)]
        public async Task<IActionResult> Create(SingleLevelTenantDto input)
        {
            // This adds a new, single level Tenant
            var status = await _authTenantAdmin.AddSingleTenantAsync(input.TenantName, input.TenantRolesName);

            // Handle errors or go to the Index page
            return status.HasErrors
                ? RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() })
                : RedirectToAction(nameof(Index), new { message = status.Message });
        }


        [HasPermission(Example3Permissions.TenantUpdate)]
        public async Task<IActionResult> Edit(int id)
        {
            // Returns the tenant information in a SingleLevelTenantDto record
            return View(await SingleLevelTenantDto.SetupForUpdateAsync(_authTenantAdmin, id));
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [HasPermission(Example3Permissions.TenantUpdate)]
        public async Task<IActionResult> Edit(SingleLevelTenantDto input)
        {
            // This updates the name of this tenant to the <see param="newTenantLevelName"/>.
            // This also means all the children underneath need to have their full name updated too
            // This method uses the <see cref="ITenantChangeService"/> you provided via the <see cref="RegisterExtensions.RegisterTenantChangeService"/>
            // to update the application's tenant data.
            var status = await _authTenantAdmin
                .UpdateTenantNameAsync(input.TenantId, input.TenantName);

            // Handle errors or go to the Index page
            return status.HasErrors
                ? RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() })
                : RedirectToAction(nameof(Index), new { message = status.Message });
        }


        [HasPermission(Example3Permissions.TenantDelete)]
        public async Task<IActionResult> Delete(int id)
        {
            // This returns a tenant, with TenantRoles and its Parent but no children, that has the given TenantId
            var status = await _authTenantAdmin.GetTenantViaIdAsync(id);

            // Handle errors
            if (status.HasErrors)
                return RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() });

            // Convert the tenant record in status.Result to a SingleLevelTenantDto
            return View(new SingleLevelTenantDto
            {
                TenantId = id,
                TenantName = status.Result.TenantFullName
            });
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [HasPermission(Example3Permissions.TenantDelete)]
        public async Task<IActionResult> Delete(SingleLevelTenantDto input)
        {
            // This will delete the tenant (and all its children if the data is hierarchical) and uses the <see cref="ITenantChangeService"/>,
            // but only if no AuthP user are linked to this tenant (it will return errors listing all the AuthP user that are linked to this tenant
            // This method uses the <see cref="ITenantChangeService"/> you provided via the <see cref="RegisterExtensions.RegisterTenantChangeService{TTenantChangeService}"/>
            // to delete the application's tenant data.
            var status = await _authTenantAdmin.DeleteTenantAsync(input.TenantId);

            // Handle errors
            return status.HasErrors
                ? RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() })
                : RedirectToAction(nameof(Index), new { message = status.Message });
        }


        [HasPermission(Example3Permissions.TenantAccessData)]
        public async Task<IActionResult> StartAccess([FromServices] ILinkToTenantDataService service, int id)
        {
            // This returns the UserId from the current user
            var currentUser = User.GetUserIdFromUser();

            // This will change the DataKey to a different tenant than the current user's DataKey
            // This does this by creating a cookie that contains a DataKey that will replace the current user's DataKey claim
            var status = await service.StartLinkingToTenantDataAsync(currentUser, id);

            // Handle errors
            return status.HasErrors
                ? RedirectToAction(nameof(ErrorDisplay),
                    new { errorMessage = status.GetAllErrors() })
                : RedirectToAction(nameof(Index), new { message = status.Message });
        }


        public IActionResult StopAccess([FromServices] ILinkToTenantDataService service, bool gotoHome)
        {
            // This returns the UserId from the current user
            var currentUser = User.GetUserIdFromUser();

            // This stops the current user's DataKey being set by the <see cref="StartLinkingToTenantDataAsync"/> method.
            // It simply deletes the <see cref="AccessTenantDataCookie"/>
            service.StopLinkingToTenant();

            // Decide what view to bo to.
            return gotoHome 
                ? RedirectToAction(nameof(Index), "Home") 
                : RedirectToAction(nameof(Index), new { message = "Finished linking to tenant's data" });
        }

        public ActionResult ErrorDisplay(string errorMessage)
        {
            return View((object)errorMessage);
        }
    }
}

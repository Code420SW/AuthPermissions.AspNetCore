// Copyright (c) 2022 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPermissions;
using AuthPermissions.AdminCode;

namespace Example3.InvoiceCode.Services;

/// <summary>
/// This adds the tenant name as a claim. This speeds up the showing of the tenant name in the display
/// </summary>
public class AddTenantNameClaim : IClaimsAdder
{
    public const string TenantNameClaimType = "TenantName";

    private readonly IAuthUsersAdminService _userAdmin;

    public AddTenantNameClaim(IAuthUsersAdminService userAdmin)
    {
        _userAdmin = userAdmin;
    }

    public async Task<Claim> AddClaimToUserAsync(string userId)
    {
        // Get the user name from the passed Id
        var user = (await _userAdmin.FindAuthUserByUserIdAsync(userId)).Result;

        // TenantNameClaimType = const string TenantNameClaimType = "TenantName" (see above)
        // Create a new claim with the full tenant name
        return user?.UserTenant?.TenantFullName == null
            ? null
            : new Claim(TenantNameClaimType, user.UserTenant.TenantFullName);
    }

    public static string GetTenantNameFromUser(ClaimsPrincipal user)
    {
        // Extract the value for the claim whose type is "TenantName" from the passed user record
        return user?.Claims.FirstOrDefault(x => x.Type == TenantNameClaimType)?.Value;
    }
}
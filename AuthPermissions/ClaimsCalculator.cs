// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.BaseCode;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.DataLayer.Classes;
using AuthPermissions.BaseCode.DataLayer.Classes.SupportTypes;
using AuthPermissions.BaseCode.DataLayer.EfCode;
using AuthPermissions.BaseCode.PermissionsCode;
using Microsoft.EntityFrameworkCore;

namespace AuthPermissions
{
    /// <summary>
    /// This service returns the authPermission claims for an AuthUser
    /// and any extra claims registered using AuthP's AddClaimToUser method when registering AuthP
    /// </summary>
    public class ClaimsCalculator : IClaimsCalculator
    {
        private readonly AuthPermissionsDbContext _context;
        private readonly AuthPermissionsOptions _options;
        private readonly IEnumerable<IClaimsAdder> _claimsAdders;

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="claimAdders"></param>
        public ClaimsCalculator(AuthPermissionsDbContext context, 
            AuthPermissionsOptions options,
                IEnumerable<IClaimsAdder> claimAdders)
        {
            _context = context;
            _options = options;
            _claimsAdders = claimAdders;
        }

        /// <summary>
        /// This will return the required AuthP claims, plus any extra claims from registered <see cref="IClaimsAdder"/> methods  
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<List<Claim>> GetClaimsForAuthUserAsync(string userId)
        {
            var result = new List<Claim>();

            //
            // Get the user record from the db
            // Load any associated tenants
            //
            var userWithTenant = await _context.AuthUsers.Where(x => x.UserId == userId)
                .Include(x => x.UserTenant)
                .SingleOrDefaultAsync();

            //
            // Bail if the user wasn't found or the user account is disabled
            //
            if (userWithTenant == null || userWithTenant.IsDisabled)
                return result;

            //
            // Created the packed permissions that are user-specific and "auto add" for an associated tenant (if any)
            //
            // If we have some permissions, build the new Claims record by setting the "Permissions" element
            //
            var permissions = await CalcPermissionsForUserAsync(userId);
            if (permissions != null) 
                result.Add(new Claim(PermissionConstants.PackedPermissionClaimType, permissions));

            //
            // If needed, build a list of Claim records associated with multi-tenant scenarions.
            //
            if (_options.TenantType.IsMultiTenant())
                result.AddRange(GetMultiTenantClaims(userWithTenant.UserTenant));

            //
            // Invoke and user-defined IClaimsAdder methods registered by
            // RegisterAddClaimToUser<TClaimsAdder> during setup
            //
            foreach (var claimsAdder in _claimsAdders)
            {
                var extraClaim = await claimsAdder.AddClaimToUserAsync(userId);
                if (extraClaim != null)
                    result.Add(extraClaim);
            }

            return result;
        }

        //------------------------------------------------------------------------------
        //private methods

        /// <summary>
        /// This is called if the Permissions that a user needs calculating.
        /// It looks at what permissions the user has based on their roles
        /// </summary>
        /// <param name="userId"></param>
        /// <returns>a string containing the packed permissions, or null if no permissions</returns>
        private async Task<string> CalcPermissionsForUserAsync(string userId)
        {
            //
            // Query the db and get all the packed permissions associated with the userId.
            //
            var permissionsForAllRoles = await _context.UserToRoles
                .Where(x => x.UserId == userId)
                .Select(x => x.Role.PackedPermissionsInRole)
                .ToListAsync();

            //
            // If this is a multi-tenant application...
            // Get the packed permissions for any "auto add" roles associated with the tenant.
            // If any were found, add them to the user-specific list of packed permissions created above
            //
            if (_options.TenantType.IsMultiTenant())
            {
                //We need to add any RoleTypes.TenantAdminAdd for a tenant user

                var autoAddPermissions = await _context.AuthUsers
                    .Where(x => x.UserId == userId && x.TenantId != null)
                    .SelectMany(x => x.UserTenant.TenantRoles
                        .Where(y => y.RoleType == RoleTypes.TenantAutoAdd)
                        .Select(z => z.PackedPermissionsInRole))
                    .ToListAsync();

                if (autoAddPermissions.Any())
                    permissionsForAllRoles.AddRange(autoAddPermissions);
            }

            //
            // Bail if nothing was found
            //
            if (!permissionsForAllRoles.Any())
                return null;

            //thanks to https://stackoverflow.com/questions/5141863/how-to-get-distinct-characters
            //
            // Mash all the permissions together and eliminate duplicates
            //
            var packedPermissionsForUser = 
                new string(string.Concat(permissionsForAllRoles).Distinct().ToArray());

            return packedPermissionsForUser;
        }

        /// <summary>
        /// This adds the correct claims for a multi-tenant application
        /// </summary>
        /// <param name="tenant"></param>
        /// <returns></returns>
        private List<Claim> GetMultiTenantClaims(Tenant tenant)
        {
            var result = new List<Claim>();

            // 
            // Return and empty list of no tenant
            //
            if (tenant == null)
                return result;

            //
            // This calculates the data key for given tenant.
            // If it is a single layer multi-tenant it will by the TenantId as a string
            // If it is a hierarchical multi-tenant it will contains a concatenation of the tenantsId in the parents as well
            //
            var dataKey = tenant.GetTenantDataKey();


            // 
            // Create a new Claims and add the DataKey to the "DataKey" element
            //
            result.Add(new Claim(PermissionConstants.DataKeyClaimType, dataKey));


            //
            // If sharding is enabled, add database info to the "DatabaseInfoName" element
            if (_options.TenantType.IsSharding())
            {
                result.Add(new Claim(PermissionConstants.DatabaseInfoNameType, tenant.DatabaseInfoName));
            }

            return result;
        }
    }
}
// Copyright (c) 2022 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPermissions;
using AuthPermissions.BaseCode.CommonCode;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace ExamplesCommonCode.IdentityCookieCode;

/// <summary>
/// This contains a method that will periodically refresh the claims of each logged-in user 
/// </summary>
public static class PeriodicCookieEvent
{
    /// <summary>
    /// Used in the "periodically update user's claims" feature
    /// </summary>
    public const string TimeToRefreshUserClaimType = "TimeToRefreshUserClaim";

    /// <summary>
    /// This method will be called on every HTTP request where a user is logged in (therefore you should keep the No change code quick)
    /// This method implements a way to update user's claims defined by a claim with the Type 
    /// <see cref="TimeToRefreshUserClaimType"/>, which contains the time by which the refresh should occur.
    /// </summary>
    /// <param name="context"></param>
    public static async Task PeriodicRefreshUsersClaims(CookieValidatePrincipalContext context)
    {
        var originalClaims = context.Principal.Claims.ToList();

        //
        // Is the cookie expired?
        //
        if (originalClaims.GetClaimDateTimeTicksValue(TimeToRefreshUserClaimType) < DateTime.UtcNow)
        {
            //Need to refresh the user's claims 
            var userId = originalClaims.GetUserIdFromClaims();
            if (userId == null)
                //this shouldn't happen, but best to return
                return;

            // Get service of type T from the System.IServiceProvider.
            var claimsCalculator = context.HttpContext.RequestServices.GetRequiredService<IClaimsCalculator>();

            // This will return the AuthP claims to be added to the Cookie or JWT token
            var newClaims = await claimsCalculator.GetClaimsForAuthUserAsync(userId);

            // First remove all the items in newClaims from originalClaims leaving just the claims that we won't change
            // Then add the resulting original, unchanged claims to the new claims.
            newClaims.AddRange(originalClaims.RemoveUpdatedClaimsFromOriginalClaims(newClaims)); //Copy over unchanged claims

            // Create a new cookie with the updated claims
            var identity = new ClaimsIdentity(newClaims, "Cookie");

            //Initializes a new instance of the System.Security.Claims.ClaimsPrincipal class
            //     from the specified identity.
            var newPrincipal = new ClaimsPrincipal(identity);

            // Called to replace the claims principal. The supplied principal will replace the
            //     value of the Principal property, which determines the identity of the authenticated
            //     request.
            context.ReplacePrincipal(newPrincipal);

            // If true, the cookie will be renewed
            context.ShouldRenew = true;
        }
    }

    private static IEnumerable<Claim> RemoveUpdatedClaimsFromOriginalClaims(this List<Claim> originalClaims, List<Claim> newClaims)
    {
        // Build a list of the types of the claims in newClaims
        var newClaimTypes = newClaims.Select(x => x.Type);

        // Update the originalClaims with everything except the claim types represented in the newClaims parameter
        return originalClaims.Where(x => !newClaimTypes.Contains(x.Type));
    }
}
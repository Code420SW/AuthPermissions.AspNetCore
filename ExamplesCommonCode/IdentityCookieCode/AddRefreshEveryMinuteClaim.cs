// Copyright (c) 2022 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPermissions;

namespace ExamplesCommonCode.IdentityCookieCode;

public class AddRefreshEveryMinuteClaim : IClaimsAdder
{
    public Task<Claim> AddClaimToUserAsync(string userId)
    {
        // const string TimeToRefreshUserClaimType = "TimeToRefreshUserClaim"
        // CreateClaimDateTimeTicks is a string extension which creates a claim from the string (as the type)
        //   and the parameter as the value (which is converted to a string).
        // Create a new claim set one minute from now
        var claim = PeriodicCookieEvent.TimeToRefreshUserClaimType
            .CreateClaimDateTimeTicks(new TimeSpan(0, 0, 1, 0));

        // Return the claim
        return Task.FromResult(claim);
    }
}
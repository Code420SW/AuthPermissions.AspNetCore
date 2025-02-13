﻿// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Threading.Tasks;
using AuthPermissions.BaseCode.SetupCode;
using AuthPermissions.BulkLoadServices.Concrete;
using AuthPermissions.SetupCode;
using Microsoft.AspNetCore.Identity;

namespace AuthPermissions.AspNetCore.Services
{
    /// <summary>
    /// This is a working example of how to build a <see cref="IFindUserInfoService"/> service
    /// that is used by the the <see cref="BulkLoadUsersService"/> to provide the actual userId (and userName)
    /// from the applications authentication provider.
    /// This works for the Individual Accounts authentication provider
    /// </summary>
    public class IndividualAccountUserLookup : IFindUserInfoService
    {
        private readonly UserManager<IdentityUser> _userManager;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="userManager"></param>
        public IndividualAccountUserLookup(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        /// <summary>
        /// This should find an user in the authentication provider using the <see cref="BulkLoadUserWithRolesTenant.UniqueUserName"/>.
        /// It returns userId and its user name (if no user found with that uniqueName, then
        /// </summary>
        /// <param name="uniqueName"></param>
        /// <returns>a class containing a UserIf and UserName property, or null if not found</returns>
        public async Task<FindUserInfoResult> FindUserInfoAsync(string uniqueName)
        {
            // Get the user's IdentityUser record based on the user name
            var user = await _userManager.FindByNameAsync(uniqueName);

            // Package the user Id and name in a FindUserInfoResult.
            return (user == null ? null : new FindUserInfoResult(user.Id, user.UserName));
        }
    }
}
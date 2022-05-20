// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using RunMethodsSequentially;

namespace AuthPermissions.AspNetCore.StartupServices
{
    /// <summary>
    /// This is a complex method that can handle a individual account user with a 
    /// personalized IdentityUser type
    /// </summary>
    public class StartupServiceIndividualAccountsAddSuperUser<TIdentityUser> : IStartupServiceToRunSequentially
        where TIdentityUser : IdentityUser, new()
    {
        /// <summary>
        /// This must be after migrations, and after the adding demo users startup service.
        /// </summary>
        public int OrderNum { get; } = -1;

        /// <summary>
        /// This will ensure that a user who's email/password is held in the "SuperAdmin" section of 
        /// the appsettings.json file is in the individual users account authentication database
        /// </summary>
        /// <param name="scopedServices">This should be a scoped service</param>
        /// <returns></returns>
        public async ValueTask ApplyYourChangeAsync(IServiceProvider scopedServices)
        {
            // Grab an instance of the UserManager service
            var userManager = scopedServices.GetRequiredService<UserManager<TIdentityUser>>();

            // Read the "SuperAdmin" section os appsettings.json and returns the email, password tuple, or null, null
            var (email, password) = scopedServices.GetSuperUserConfigData();

            // If not (null, null) add the user (if they don'r exist already).
            if (!string.IsNullOrEmpty(email))
                await CheckAddNewUserAsync(userManager, email, password);
        }

        /// <summary>
        /// This will add a user with the given email if they don't all ready exist
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private static async Task CheckAddNewUserAsync(UserManager<TIdentityUser> userManager, string email, string password)
        {
            // Try to find the passed user in the authentication db
            var user = await userManager.FindByEmailAsync(email);

            // Nothing more to do if found
            if (user != null)
                return;

            // Create a new record for the user (typically IdentityUser, but can be anything that UserManager can work with).
            user = new TIdentityUser { UserName = email, Email = email };

            // Try to create the user
            var result = await userManager.CreateAsync(user, password);

            // Throw on errors
            if (!result.Succeeded)
            {
                var errorDescriptions = string.Join("\n", result.Errors.Select(x => x.Description));
                throw new InvalidOperationException(
                    $"Tried to add user {email}, but failed. Errors:\n {errorDescriptions}");
            }
        }
    }
}

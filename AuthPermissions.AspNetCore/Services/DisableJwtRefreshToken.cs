// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.DataLayer.EfCode;
using Microsoft.EntityFrameworkCore;

namespace AuthPermissions.AspNetCore.Services
{
    /// <summary>
    /// This service allows you to mark the Jwt Refresh Token as 'used' so that the JWT token cannot be refreshed
    /// </summary>
    public class DisableJwtRefreshToken : IDisableJwtRefreshToken
    {
        private readonly AuthPermissionsDbContext _context;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="context"></param>
        public DisableJwtRefreshToken(AuthPermissionsDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// This will mark the latest, valid RefreshToken as invalid.
        /// Call this a) when a user logs out, or b) you want to log out an active user when the JTW times out
        /// </summary>
        /// <param name="userId"></param>
        public async Task MarkJwtRefreshTokenAsUsedAsync(string userId)
        {
            // Find all the RefreshTokens in the db associated with the user that
            // are still valid sorted in descending date order, and then return
            // the first one (may be null if no RefreshTokens exist for the user
            // that are not expired).
            var latestValidRefreshToken = await _context.RefreshTokens
                .Where(x => x.UserId == userId && !x.IsInvalid)
                .OrderByDescending(x => x.AddedDateUtc)
                .FirstOrDefaultAsync();

            // If we got a valid RefreshToken for the user, mark it as invalid
            // and save it to the database.
            if (latestValidRefreshToken != null)
            {
                latestValidRefreshToken.MarkAsInvalid();
                var status = await _context.SaveChangesWithChecksAsync();
                status.IfErrorsTurnToException();
            }
        }
    }
}
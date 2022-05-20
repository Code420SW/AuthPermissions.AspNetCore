// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.BaseCode.CommonCode;
using Example3.InvoiceCode.Dtos;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StatusGeneric;

namespace Example3.InvoiceCode.Services;

public class UserRegisterInviteService : IUserRegisterInviteService
{
    private readonly IAuthTenantAdminService _tenantAdminService;
    private readonly IAuthUsersAdminService _authUsersAdmin;
    private readonly IEncryptDecryptService _encryptorService;
    private readonly UserManager<IdentityUser> _userManager;

    private readonly Dictionary<TenantVersionTypes, List<string>> _rolesToAddUserForVersions = new()
    {
        { TenantVersionTypes.Free, new List<string> { "Tenant User" } },
        { TenantVersionTypes.Pro, new List<string> { "Tenant User", "Tenant Admin" } },
        { TenantVersionTypes.Enterprise, new List<string> { "Tenant User", "Tenant Admin" } }
    };

    private readonly Dictionary<TenantVersionTypes, List<string>> _rolesToAddTenantForVersion = new()
    {
        { TenantVersionTypes.Free, null },
        { TenantVersionTypes.Pro, new List<string> { "Tenant Admin" } },
        { TenantVersionTypes.Enterprise, new List<string> { "Tenant Admin", "Enterprise" } },
    };

    public UserRegisterInviteService(IAuthTenantAdminService tenantAdminService, 
        IAuthUsersAdminService authUsersAdmin, IEncryptDecryptService encryptorService, 
        UserManager<IdentityUser> userManager)
    {
        _tenantAdminService = tenantAdminService;
        _authUsersAdmin = authUsersAdmin;
        _encryptorService = encryptorService;
        _userManager = userManager;
    }

    /// <summary>
    /// This does three things (with lots of checks)
    /// - Adds the new user to the the individual account
    /// - Adds an AuthUser for this person
    /// - Creates the tenant with the correct tenant roles
    /// NOTE: On return you MUST sign in the user using the email and password they provided via the individual accounts signInManager
    /// </summary>
    /// <param name="dto">The information from the user</param>
    /// <returns>Status with the individual accounts user</returns>
    public async Task<IStatusGeneric<IdentityUser>> AddUserAndNewTenantAsync(CreateTenantDto dto)
    {
        // Create the Master status and preset the message
        var status = new StatusGenericHandler<IdentityUser>
        {
            Message =
                $"Successfully created the tenant called '{dto.TenantName}' and registered you as the tenant admin"
        };

        // Get the enum value for the dto.Version type
        var tenantVersion = dto.GetTenantVersionType();

        // Chexk for errors and throw
        if (tenantVersion == TenantVersionTypes.NotSet)
            throw new AuthPermissionsException("The Version string in the dto wasn't set properly");

        // Check if tenant name is available
        // Filter a list of all tenants and look for one that is the same as dto.TenantName
        // If found, add the error to Master status and return
        if (_tenantAdminService.QueryTenants().Any(x => x.TenantFullName == dto.TenantName))
            return status.AddError($"The tenant name '{dto.TenantName}' is already taken", new []{nameof(CreateTenantDto.TenantName) });

        // Add a new individual users account user (IdentityUser), or return existing user
        // Will sent back error if already an AuthUser, because a user can't be linked to multiple tenants
        var userStatus = await GetIndividualAccountUserAndCheckNotAuthUser(dto.Email, dto.Password);

        // If errors, merge them into Master status and return
        if (status.CombineStatuses(userStatus).HasErrors)
            return status;

        // Now we can create the tenant, with the correct tenant roles
        var tenantStatus = await _tenantAdminService.AddSingleTenantAsync(dto.TenantName, _rolesToAddTenantForVersion[tenantVersion]);
        if (status.CombineStatuses(tenantStatus).HasErrors)
            return status;

        // This creates a user, with the roles suitable for the version of the version of the app
        status.CombineStatuses(await _authUsersAdmin.AddNewUserAsync(userStatus.Result.Id, dto.Email, null,
            _rolesToAddUserForVersions[dto.GetTenantVersionType()], dto.TenantName));

        // Return the IdentityUser record in Master status.Result
        status.SetResult(userStatus.Result);

        return status;
    }

    /// <summary>
    /// This creates a an encrypted string containing the tenantId and the user's email
    /// so that you can confirm the user is valid
    /// </summary>
    /// <param name="tenantId">Id of the tenant you want the user to join</param>
    /// <param name="emailOfJoiner">email of the user</param>
    /// <returns>encrypted string to send the user encoded to work with urls</returns>
    public string InviteUserToJoinTenantAsync(int tenantId, string emailOfJoiner)
    {
        var verify = _encryptorService.Encrypt($"{tenantId},{emailOfJoiner.Trim()}");
        return Base64UrlEncoder.Encode(verify);
    }

    /// <summary>
    /// This will take the new user's information plus the encrypted invite code and
    /// 1. decides if the invite matches the user's email
    /// 2. It will create an individual accounts user (if not there), plus a check teh user isn't already an authP user
    /// 3. Then it will create an authP user linked to the tenant they were invited to
    /// NOTE: On return you MUST sign in the user using the email and password they provided via the individual accounts signInManager
    /// </summary>
    /// <param name="email">email given to log in</param>
    /// <param name="password">password given to log in</param>
    /// <param name="inviteParam">The encrypted part of the url encoded to work with urls
    /// that was created by <see cref="InviteUserToJoinTenantAsync"/></param>
    /// <returns>Status with the individual accounts user</returns>
    public async Task<IStatusGeneric<IdentityUser>> AcceptUserJoiningATenantAsync(string email, string password, string inviteParam)
    {
        // Craete Master status
        var status = new StatusGenericHandler<IdentityUser>();

        int tenantId;
        string emailOfJoiner;
        try
        {
            // Decrypt the passed inviteParam
            var decrypted = _encryptorService.Decrypt(Base64UrlEncoder.Decode(inviteParam));

            // Whatever it is contains twp parts separated by comma
            var parts = decrypted.Split(',');
            tenantId = int.Parse(parts[0]);
            emailOfJoiner = parts[1].Trim();
        }
        catch (Exception)
        {
            //Could add a log here
            return status.AddError("Sorry, the verification failed.");
        }

        // Compare the email extracted from the inviteParam to the email entered by the user...mist match
        if (emailOfJoiner != email.Trim())
            return status.AddError("Sorry, your email didn't match the invite.");

        // Get the Tenant record for the tenantId extracted from inviteParam
        var tenant = await _tenantAdminService.QueryTenants()
            .SingleOrDefaultAsync(x => x.TenantId == tenantId);

        // Handle not found error
        if (tenant == null)
            return status.AddError("Sorry, your invite is rejected. Please talk to your admin person.");

        //Add a new individual users account user, or return existing user
        //Will sent back error if already an AuthUser, because a user can't be linked to multiple tenants
        // Do a bunch of error-checking and return the IdentityUser new/existing record in userStatus.Result
        var userStatus = await GetIndividualAccountUserAndCheckNotAuthUser(email, password);

        // Bail if errors
        if (status.CombineStatuses(userStatus).HasErrors)
            return status;

        //We add the "Tenant User" role to the invited user so that they can access the features
        status.CombineStatuses(await _authUsersAdmin.AddNewUserAsync(userStatus.Result.Id, email, null,
            new List<string> { "Tenant User" }, tenant.TenantFullName));

        // Bail if errors
        if (status.HasErrors)
            return status;

        // Return the new/existing IdentityUser record in Master status.Result
        status.SetResult(userStatus.Result);
        status.Message = $"You have successfully joined the tenant '{tenant.TenantFullName}'";
        return status;
    }

    //---------------------------------------------------------------
    //private methods

    private async Task<IStatusGeneric<IdentityUser>> GetIndividualAccountUserAndCheckNotAuthUser(string email, string password)
    {
        // Create the Master status 
        var status = new StatusGenericHandler<IdentityUser>();

        // Query UserMananger for a user with the passed email
        // ONLY CHECKING AUTHENTICATION
        var user = await _userManager.FindByEmailAsync(email);

        // If a user was not found...
        if (user == null)
        {
            // Build the IdentityUser record and create a Usermanager record
            user = new IdentityUser { UserName = email, Email = email };
            var result = await _userManager.CreateAsync(user, password);

            // Check IdentityResult and if the cretion process failed...
            if (!result.Succeeded)
            {
                // Extract all IdentityResult error to a list and then iterate over the list to create
                // and error message in Master status
                result.Errors.Select(x => x.Description).ToList().ForEach(error => status.AddError(error));
            }
        }

        // Otherwise, we found the user...
        // Verify the email/password match.
        // If they don't, add an error message to Master status
        else if(!await _userManager.CheckPasswordAsync(user, password))
            status.AddError("The user was already known, but the password was wrong.");


        // NOW CHECK AUTHORIZATION.....
        // Check if user is already in the AuthUsers (because a AuthUser can only be linked to one tenant)
        // If the user is found, the AuthUser record is returned in status.Result
        // If the user WAS found, create and error meaasge in Master status
        if ((await _authUsersAdmin.FindAuthUserByEmailAsync(email)).Result != null)
            status.AddError("You are already registered as a user, which means you can't ask to access another tenant.");

        // Return the authentication (IdentityUser) record (will not be null) through status.Result
        return status.SetResult(user);
    }
}
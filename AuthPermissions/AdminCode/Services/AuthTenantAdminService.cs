﻿// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using AuthPermissions.BaseCode;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.DataLayer.Classes;
using AuthPermissions.BaseCode.DataLayer.Classes.SupportTypes;
using AuthPermissions.BaseCode.DataLayer.EfCode;
using AuthPermissions.BaseCode.SetupCode;
using AuthPermissions.SetupCode.Factories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using StatusGeneric;

namespace AuthPermissions.AdminCode.Services
{
    /// <summary>
    /// This provides CRUD services for tenants
    /// </summary>
    public class AuthTenantAdminService : IAuthTenantAdminService
    {
        private readonly AuthPermissionsDbContext _context;
        private readonly AuthPermissionsOptions _options;
        private readonly IAuthPServiceFactory<ITenantChangeService> _tenantChangeServiceFactory;
        private readonly ILogger _logger;

        private readonly TenantTypes _tenantType;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tenantChangeServiceFactory"></param>
        /// <param name="logger"></param>
        public AuthTenantAdminService(AuthPermissionsDbContext context, 
            AuthPermissionsOptions options, 
            IAuthPServiceFactory<ITenantChangeService> tenantChangeServiceFactory,
            ILogger<AuthTenantAdminService> logger)
        {
            _context = context;
            _options = options;
            _tenantChangeServiceFactory = tenantChangeServiceFactory;
            _logger = logger;

            _tenantType = options.TenantType;
        }

        /// <summary>
        /// This simply returns a IQueryable of Tenants
        /// </summary>
        /// <returns>query on the AuthP database</returns>
        public IQueryable<Tenant> QueryTenants()
        {
            return _context.Tenants;
        }

        /// <summary>
        /// This query returns all the end leaf Tenants, which is the bottom of the hierarchy (i.e. no children below it)
        /// </summary>
        /// <returns>query on the AuthP database</returns>
        public IQueryable<Tenant> QueryEndLeafTenants()
        {
            return _tenantType.IsSingleLevel()
                ? QueryTenants()
                : _context.Tenants.Where(x => !x.Children.Any());
        }

        /// <summary>
        /// This returns a list of all the RoleNames that can be applied to a Tenant
        /// </summary>
        /// <returns></returns>
        public async Task<List<string>> GetRoleNamesForTenantsAsync()
        {
            return await _context.RoleToPermissions
                .Where(x => x.RoleType == RoleTypes.TenantAutoAdd || x.RoleType == RoleTypes.TenantAdminAdd)
                .Select(x => x.RoleName)
                .ToListAsync();
        }

        /// <summary>
        /// This returns a tenant, with TenantRoles and its Parent but no children, that has the given TenantId
        /// </summary>
        /// <param name="tenantId">primary key of the tenant you are looking for</param>
        /// <returns>Status. If successful, then contains the Tenant</returns>
        public async Task<IStatusGeneric<Tenant>> GetTenantViaIdAsync(int tenantId)
        {
            // Create the Master status
            var status = new StatusGenericHandler<Tenant>();

            // Get the tenant record from the db
            var result = await _context.Tenants
                .Include(x => x.Parent)
                .Include(x => x.TenantRoles)
                .SingleOrDefaultAsync(x => x.TenantId == tenantId);

            // Handle errors
            return result == null 
                ? status.AddError("Could not find the tenant you were looking for.") 
                : status.SetResult(result);
        }

        /// <summary>
        /// This returns a list of all the child tenants
        /// </summary>
        /// <param name="tenantId">primary key of the tenant you are looking for</param>
        /// <returns>A list of child tenants for this tenant (can be empty)</returns>
        public async Task<List<Tenant>> GetHierarchicalTenantChildrenViaIdAsync(int tenantId)
        {
            var tenant = await _context.Tenants
                .SingleOrDefaultAsync(x => x.TenantId == tenantId);
            if (tenant == null)
                throw new AuthPermissionsException($"Could not find the tenant with id of {tenantId}");

            if (!tenant.IsHierarchical)
                throw new AuthPermissionsException("This method is only for hierarchical tenants");

            return await _context.Tenants
                .Include(x => x.Parent)
                .Include(x => x.Children)
                .Where(x => x.ParentDataKey.StartsWith(tenant.GetTenantDataKey()))
                .ToListAsync();
        }

        /// <summary>
        /// This adds a new, single level Tenant
        /// </summary>
        /// <param name="tenantName">Name of the new single-level tenant (must be unique)</param>
        /// <param name="tenantRoleNames">Optional: List of tenant role names</param>
        /// <param name="hasOwnDb">Needed if sharding: Is true if this tenant has its own database, else false</param>
        /// <param name="databaseInfoName">This is the name of the database information in the shardingsettings file.</param>
        /// <returns>A status with any errors found</returns>
        public async Task<IStatusGeneric> AddSingleTenantAsync(string tenantName,
                                                               List<string> tenantRoleNames = null,
                                                               bool? hasOwnDb = null,
                                                               string databaseInfoName = null)
        {
            // Create the Master status and preset the message
            var status = new StatusGenericHandler { Message = $"Successfully added the new tenant {tenantName}." };

            // Make sure the tenant type is consistent with the function's purpose
            if (!_tenantType.IsSingleLevel())
                throw new AuthPermissionsException(
                    $"You cannot add a single tenant because the tenant configuration is {_tenantType}");

            // Find the ITenantChangeService registered in the DI.
            // Procedure will throw if nothing found.
            var tenantChangeService = _tenantChangeServiceFactory.GetService();

            // Begin a transaction...
            await using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                // Build a list of RoleToPermissions for the past list of roles
                var tenantRolesStatus = await GetRolesWithChecksAsync(tenantRoleNames);

                // Combine the results into Master status
                status.CombineStatuses(tenantRolesStatus);

                // Try to create the new Tenant
                // *** The tenant is stored in the Result parameter ***
                var newTenantStatus = Tenant.CreateSingleTenant(tenantName, tenantRolesStatus.Result);

                // Combine the status into Master status and return if any errors
                if (status.CombineStatuses(newTenantStatus).HasErrors)
                    return status;

                // If we are using sharding...
                if (_tenantType.IsSharding())
                {
                    // Error-check the passed hasOwnDb is set correctly
                    if (hasOwnDb == null)
                        status.AddError($"The {nameof(hasOwnDb)} parameter must be set to true or false when sharding is turned on.",
                            nameof(hasOwnDb).CamelToPascal());
                    // Otherwise, make sure another tenant isn't using the same db
                    else
                        status.CombineStatuses(await CheckHasOwnDbIsValidAsync((bool)hasOwnDb, databaseInfoName));

                    // Bail if any errors so far
                    if (status.HasErrors)
                        return status;

                    // Update the Tenant's sharding parameters
                    newTenantStatus.Result.UpdateShardingState(
                        databaseInfoName ?? _options.ShardingDefaultDatabaseInfoName,
                        (bool)hasOwnDb);
                }

                // Save the new Tenant to the db
                _context.Add(newTenantStatus.Result);
                status.CombineStatuses(await _context.SaveChangesWithChecksAsync());

                // Bail on any errors (triggers a rollback)
                if (status.HasErrors)
                    return status;

                // Using the service found above...
                // Call the application-specific procedure to do application-specific stuff
                var errorString = await tenantChangeService.CreateNewTenantAsync(newTenantStatus.Result);
                if (errorString != null)
                    return status.AddError(errorString);

                await transaction.CommitAsync();
            }
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to create a tenant failed with a system error. Please contact the admin team.");
            }

            return status;
        }

        /// <summary>
        /// This adds a new Hierarchical Tenant, liking it into the parent (which can be null)
        /// </summary>
        /// <param name="tenantName">Name of the new tenant. This will be prefixed with the parent's tenant name to make it unique</param>
        /// <param name="parentTenantId">The primary key of the parent. If 0 then the new tenant is at the top level</param>
        /// <param name="tenantRoleNames">Optional: List of tenant role names</param>
        /// <param name="hasOwnDb">Needed if sharding: Is true if this tenant has its own database, else false</param>
        /// <param name="databaseInfoName">This is the name of the database information in the shardingsettings file.</param>
        /// <returns>A status with any errors found</returns>
        public async Task<IStatusGeneric> AddHierarchicalTenantAsync(string tenantName, int parentTenantId,
            List<string> tenantRoleNames = null, bool? hasOwnDb = false, string databaseInfoName = null)
        {
            var status = new StatusGenericHandler { Message = $"Successfully added the new tenant {tenantName}." };

            if (!_tenantType.IsHierarchical())
                throw new AuthPermissionsException(
                    $"You must set the {nameof(AuthPermissionsOptions.TenantType)} before you can use tenants");
            if (tenantName.Contains('|'))
                return status.AddError(
                    "The tenant name must not contain the character '|' because that character is used to separate the names in the hierarchical order",
                        nameof(tenantName).CamelToPascal());

            var tenantChangeService = _tenantChangeServiceFactory.GetService();

            using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                Tenant parentTenant = null;
                if (parentTenantId != 0)
                {
                    //We need to find the parent
                    parentTenant = await _context.Tenants.SingleOrDefaultAsync(x => x.TenantId == parentTenantId);
                    if (parentTenant == null)
                        return status.AddError("Could not find the parent tenant you asked for.");

                    if (!parentTenant.IsHierarchical)
                        throw new AuthPermissionsException(
                            "attempted to add a Hierarchical tenant to a single-level tenant, which isn't allowed");
                }

                var fullTenantName = Tenant.CombineParentNameWithTenantName(tenantName, parentTenant?.TenantFullName);
                status.Message = $"Successfully added the new hierarchical tenant {fullTenantName}.";

                var tenantRolesStatus = await GetRolesWithChecksAsync(tenantRoleNames);
                status.CombineStatuses(tenantRolesStatus);
                var newTenantStatus = Tenant.CreateHierarchicalTenant(fullTenantName, parentTenant, tenantRolesStatus.Result);
                
                if (status.CombineStatuses(newTenantStatus).HasErrors)
                    return status;

                if (_tenantType.IsSharding())
                {
                    if (parentTenant != null)
                    {
                        //If there is a parent we use its sharding settings
                        //But to make sure the user thinks their values are used we send back errors if they are different 

                        if (hasOwnDb != null && parentTenant.HasOwnDb != hasOwnDb)
                            status.AddError(
                                $"The {nameof(hasOwnDb)} parameter doesn't match the parent's " +
                                $"{nameof(Tenant.HasOwnDb)}. Set the {nameof(hasOwnDb)} " +
                                $"parameter to null to use the parent's {nameof(Tenant.HasOwnDb)} value.",
                                nameof(hasOwnDb).CamelToPascal());

                        if (databaseInfoName != null &&
                            parentTenant.DatabaseInfoName != databaseInfoName)
                            status.AddError(
                                $"The {nameof(databaseInfoName)} parameter doesn't match the parent's " +
                                $"{nameof(Tenant.DatabaseInfoName)}. Set the {nameof(databaseInfoName)} " +
                                $"parameter to null to use the parent's {nameof(Tenant.DatabaseInfoName)} value.",
                                nameof(databaseInfoName).CamelToPascal());


                        hasOwnDb = parentTenant.HasOwnDb;
                        databaseInfoName = parentTenant.DatabaseInfoName;

                        status.CombineStatuses(await CheckHasOwnDbIsValidAsync((bool)hasOwnDb, databaseInfoName));
                    }
                    else
                    {

                        if (hasOwnDb == null)
                            return status.AddError(
                                $"The {nameof(hasOwnDb)} parameter must be set to true or false if there is no parent and sharding is turned on.",
                                nameof(hasOwnDb).CamelToPascal());

                        status.CombineStatuses(await CheckHasOwnDbIsValidAsync((bool)hasOwnDb, databaseInfoName));
                    }

                    if (status.HasErrors)
                        return status;

                    newTenantStatus.Result.UpdateShardingState(
                        databaseInfoName ?? _options.ShardingDefaultDatabaseInfoName,
                        (bool)hasOwnDb);
                }

                _context.Add(newTenantStatus.Result);
                status.CombineStatuses(await _context.SaveChangesWithChecksAsync());

                if (status.HasErrors)
                    return status;

                var errorString = await tenantChangeService.CreateNewTenantAsync(newTenantStatus.Result);
                if (errorString != null)
                    return status.AddError(errorString);

                await transaction.CommitAsync();
            }
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to delete a tenant failed with a system error. Please contact the admin team.");
            }

            return status;
        }

        /// <summary>
        /// This replaces the <see cref="Tenant.TenantRoles"/> in the tenant with <see param="tenantId"/> primary key
        /// </summary>
        /// <param name="tenantId">Primary key of the tenant to change</param>
        /// <param name="newTenantRoleNames">List of RoleName to replace the current tenant's <see cref="Tenant.TenantRoles"/></param>
        /// <returns></returns>
        public async Task<IStatusGeneric> UpdateTenantRolesAsync(int tenantId, List<string> newTenantRoleNames)
        {
            if (!_tenantType.IsMultiTenant())
                throw new AuthPermissionsException(
                    $"You must set the {nameof(AuthPermissionsOptions.TenantType)} parameter in the AuthP's options");

            var status = new StatusGenericHandler { Message = "Successfully updated the tenant's Roles." };

            var tenant = await _context.Tenants.Include(x => x.TenantRoles)
                .SingleOrDefaultAsync(x => x.TenantId == tenantId);

            if (tenant == null)
                return status.AddError("Could not find the tenant you were looking for.");

            var tenantRolesStatus = await GetRolesWithChecksAsync(newTenantRoleNames);
            if (status.CombineStatuses(tenantRolesStatus).HasErrors)
                return status;

            var updateStatus = tenant.UpdateTenantRoles(tenantRolesStatus.Result);
            if (updateStatus.HasErrors)
                return updateStatus;

            return await _context.SaveChangesWithChecksAsync();
        }

        /// <summary>
        /// This updates the name of this tenant to the <see param="newTenantLevelName"/>.
        /// This also means all the children underneath need to have their full name updated too
        /// This method uses the <see cref="ITenantChangeService"/> you provided via the <see cref="RegisterExtensions.RegisterTenantChangeService"/>
        /// to update the application's tenant data.
        /// </summary>
        /// <param name="tenantId">Primary key of the tenant to change</param>
        /// <param name="newTenantName">This is the new name for this tenant name</param>
        /// <returns></returns>
        public async Task<IStatusGeneric> UpdateTenantNameAsync(int tenantId, string newTenantName)
        {
            // Craete the Master status with preset message
            var status = new StatusGenericHandler
                { Message = $"Successfully updated the tenant's name to {newTenantName}." };

            // The new tenant name can't be null
            if (string.IsNullOrEmpty(newTenantName))
                return status.AddError("The new name was empty", nameof(newTenantName).CamelToPascal());

            // No special characters in the tenant name
            if (newTenantName.Contains('|'))
                return status.AddError(
                    "The tenant name must not contain the character '|' because that character is used to separate the names in the hierarchical order",
                        nameof(newTenantName).CamelToPascal());

            // Get the user-provided ITenantChangeService
            var tenantChangeService = _tenantChangeServiceFactory.GetService();

            // Begin the transaction...
            using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                // Get the tenant associated with the passed tenantId from the db
                var tenant = await _context.Tenants
                    .SingleOrDefaultAsync(x => x.TenantId == tenantId);

                // Bail if the tenant wasn't found
                if (tenant == null)
                    return status.AddError("Could not find the tenant you were looking for.");

                // If this is an heirarchial tenant...
                if (tenant.IsHierarchical)
                {
                    //We need to load the main tenant and any children and this is the simplest way to do that
                    var tenantsWithChildren = await _context.Tenants
                        .Include(x => x.Parent)
                        .Include(x => x.Children)
                        .Where(x => x.TenantFullName.StartsWith(tenant.TenantFullName))
                        .ToListAsync();

                    // Get the tenant record associated with the passed tenantId
                    var existingTenantWithChildren = tenantsWithChildren
                        .Single(x => x.TenantId == tenantId);

                    // This updates the tenant name and the TenantFullName for this tenant 
                    // and all its children
                    existingTenantWithChildren.UpdateTenantName(newTenantName);

                    // This is not defined in Example3.InvoiceCode.EfCoreCode: InvoiceTenantChangeService
                    // and will throw.
                    await tenantChangeService.HierarchicalTenantUpdateNameAsync(tenantsWithChildren);
                }

                // Otherwise (not a heirarchial tenant),
                else
                {
                    // This updates the tenant name and the TenantFullName for this tenant
                    tenant.UpdateTenantName(newTenantName);

                    // This is called when the name of your Tenants is changed. This is useful if you use the tenant name in your multi-tenant data.
                    // NOTE: The created application's DbContext won't have a DataKey, so you will need to use IgnoreQueryFilters on any EF Core read
                    var errorString = await tenantChangeService.SingleTenantUpdateNameAsync(tenant);

                    // Handle errors
                    if (errorString != null)
                        return status.AddError(errorString);
                }

                // Save the changes to the db and capture errors
                status.CombineStatuses(await _context.SaveChangesWithChecksAsync());

                // Commit the transaction if all is well
                // Otherwise we fall out of the try block which will invalidate the transaction
                if (status.IsValid)
                    await transaction.CommitAsync();
            }

            // Any exceptions will void the transaction
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to delete a tenant failed with a system error. Please contact the admin team.");
            }

            // All went well, set the message in Master status
            status.Message = $"Successfully updated the tenant name to '{newTenantName}'.";

            return status;
        }

        /// <summary>
        /// This moves a hierarchical tenant to a new parent (which might be null). This changes the TenantFullName and the
        /// TenantDataKey of the selected tenant and all of its children
        /// This method uses the <see cref="ITenantChangeService"/> you provided via the <see cref="RegisterExtensions.RegisterTenantChangeService"/>
        /// </summary>
        /// <param name="tenantToMoveId">The primary key of the AuthP tenant to move</param>
        /// <param name="newParentTenantId">Primary key of the new parent, if 0 then you move the tenant to top</param>
        /// <returns>status</returns>
        public async Task<IStatusGeneric> MoveHierarchicalTenantToAnotherParentAsync(int tenantToMoveId, int newParentTenantId)
        {
            var status = new StatusGenericHandler { Message = "Successfully moved the hierarchical tenant to a new parent." };

            if (!_tenantType.IsHierarchical())
                throw new AuthPermissionsException(
                    $"You cannot add a hierarchical tenant because the tenant configuration is {_tenantType}");

            if (tenantToMoveId == newParentTenantId)
                return status.AddError("You cannot move a tenant to itself.", nameof(tenantToMoveId).CamelToPascal());

            var tenantChangeService = _tenantChangeServiceFactory.GetService();

            await using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                var tenantToMove = await _context.Tenants
                    .SingleOrDefaultAsync(x => x.TenantId == tenantToMoveId);
                var originalName = tenantToMove.TenantFullName;

                var tenantsWithChildren = await _context.Tenants
                    .Include(x => x.Parent)
                    .Include(x => x.Children)
                    .Where(x => x.TenantFullName.StartsWith(tenantToMove.TenantFullName))
                    .ToListAsync();

                var existingTenantWithChildren = tenantsWithChildren
                    .Single(x => x.TenantId == tenantToMoveId);

                Tenant parentTenant = null;
                if (newParentTenantId != 0)
                {
                    //We need to find the parent
                    parentTenant = await _context.Tenants.SingleOrDefaultAsync(x => x.TenantId == newParentTenantId);
                    if (parentTenant == null)
                        return status.AddError("Could not find the parent tenant you asked for.");

                    if (tenantsWithChildren.Select(x => x.TenantFullName).Contains(parentTenant.TenantFullName))
                        return status.AddError("You cannot move a tenant one of its children.",
                            nameof(newParentTenantId).CamelToPascal());
                }

                //Now we ask the Tenant entity to do the move on the AuthP's Tenants, and capture each change
                var listOfChanges = new List<(string oldDataKey, Tenant)>();
                existingTenantWithChildren.MoveTenantToNewParent(parentTenant, tuple => listOfChanges.Add(tuple));
                var errorString = await tenantChangeService.MoveHierarchicalTenantDataAsync(listOfChanges);
                if (errorString != null)
                    return status.AddError(errorString);

                status.CombineStatuses(await _context.SaveChangesWithChecksAsync());
                status.Message = $"Successfully moved the tenant originally named '{originalName}' to " +
                                 (parentTenant == null ? "top level." : $"the new named '{existingTenantWithChildren.TenantFullName}'.");

                if (status.IsValid)
                    await transaction.CommitAsync();
            }
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to delete a tenant failed with a system error. Please contact the admin team.");
            }

            return status;
        }

        /// <summary>
        /// This will delete the tenant (and all its children if the data is hierarchical) and uses the <see cref="ITenantChangeService"/>,
        /// but only if no AuthP user are linked to this tenant (it will return errors listing all the AuthP user that are linked to this tenant
        /// This method uses the <see cref="ITenantChangeService"/> you provided via the <see cref="RegisterExtensions.RegisterTenantChangeService{TTenantChangeService}"/>
        /// to delete the application's tenant data.
        /// </summary>
        /// <returns>Status returning the <see cref="ITenantChangeService"/> service, in case you want copy the delete data instead of deleting</returns>
        public async Task<IStatusGeneric<ITenantChangeService>> DeleteTenantAsync(int tenantId)
        {
            // Create the Master status
            var status = new StatusGenericHandler<ITenantChangeService>();

            string message;

            // Find our registered ITenantChangeService (Example3.InvoiceCode.EfCoreCode: InvoiceTenantChangeService)
            // And store it in Master status.Result
            var tenantChangeService = _tenantChangeServiceFactory.GetService();
            status.SetResult(tenantChangeService);

            // Begin the transaction...
            using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                // Get the tenant record to delete from the db
                var tenantToDelete = await _context.Tenants
                    .SingleOrDefaultAsync(x => x.TenantId == tenantId);

                // Bail if not found
                if (tenantToDelete == null)
                    return status.AddError("Could not find the tenant you were looking for.");

                // Build a list of tenant IDs that are associated with the tenant to be deleted
                var allTenantIdsAffectedByThisDelete = await _context.Tenants
                    .Include(x => x.Parent)
                    .Include(x => x.Children)
                    .Where(x => x.TenantFullName.StartsWith(tenantToDelete.TenantFullName))
                    .Select(x => x.TenantId)
                    .ToListAsync();

                // Build a list of user emails who are associated with the tenant to be deleted
                var usersOfThisTenant = await _context.AuthUsers
                    .Where(x => allTenantIdsAffectedByThisDelete.Contains(x.TenantId ?? 0))
                    .Select(x => x.UserName ?? x.Email)
                    .ToListAsync();
                
                // If the tenant to be deleted or any of its children have users,
                // build a series of error messages.
                var tenantOrChildren = allTenantIdsAffectedByThisDelete.Count > 1
                    ? "tenant or its children tenants are"
                    : "tenant is";
                if (usersOfThisTenant.Any())
                    usersOfThisTenant.ForEach(x =>
                        status.AddError(
                            $"This delete is aborted because this {tenantOrChildren} linked to the user '{x}'."));

                // Bail on errors
                if (status.HasErrors)
                    return status;

                // Set the Master status message
                message = $"Successfully deleted the tenant called '{tenantToDelete.TenantFullName}'";


                // At this point whe have a list of tenants and children with which no users are associated
                //
                // If this is a heirarchial tenant...
                if (tenantToDelete.IsHierarchical)
                {
                    //need to delete all the tenants that starts with the main tenant DataKey
                    //We order the tenants with the children first in case a higher level links to a lower level
                    var tenantsInOrder = (await _context.Tenants
                        .Where(x => x.ParentDataKey.StartsWith(tenantToDelete.GetTenantDataKey()))
                        .ToListAsync())
                        .OrderByDescending(x => x.GetTenantDataKey().Count(y => y == '.'))
                        .ToList();

                    //Now we add the parent as the last
                    tenantsInOrder.Add(tenantToDelete);

                    // This is not defined in Example3.InvoiceCode.EfCoreCode: InvoiceTenantChangeService
                    // Will throw
                    var childError = await tenantChangeService.HierarchicalTenantDeleteAsync(tenantsInOrder);
                    if (childError != null)
                        return status.AddError(childError);

                    if (tenantsInOrder.Count > 0)
                    {
                        _context.RemoveRange(tenantsInOrder);
                        message += $" and its {tenantsInOrder.Count} linked tenants";
                    }
                }

                // Otherwise this is a single-level tenant...
                else
                {
                    //delete the tenant that the user defines
                    // This is used with single-level tenant to either
                    // a) delete all the application-side data with the given DataKey, or
                    // b) soft-delete the data.
                    // You should apply multiple changes within a transaction so that if any fails then any previous changes will be rolled back
                    // Notes:
                    // - The created application's DbContext won't have a DataKey, so you will need to use IgnoreQueryFilters on any EF Core read
                    // - You can provide information of what you have done by adding public parameters to this class.
                    //   The TenantAdmin <see cref="AuthTenantAdminService.DeleteTenantAsync"/> method returns your class on a successful Delete
                    var mainError = await tenantChangeService.SingleTenantDeleteAsync(tenantToDelete);

                    // Bail on errors. This will void the transaction.
                    if (mainError != null)
                        return status.AddError(mainError);

                    // Mark the tenant for deletion
                    _context.Remove(tenantToDelete);
                }

                // Prepare to save changes to the db
                status.CombineStatuses(await _context.SaveChangesWithChecksAsync());

                // If everything has gone well, Commit the transaction
                if (status.IsValid)
                    await transaction.CommitAsync();
            }

            // Any exceptions will void the transaction
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to delete a tenant failed with a system error. Please contact the admin team.");
            }

            status.Message = message + ".";
            return status;
        }

        /// <summary>
        /// This is used when sharding is enabled. It updates the tenant's <see cref="Tenant.DatabaseInfoName"/> and
        /// <see cref="Tenant.HasOwnDb"/> and calls the  <see cref="ITenantChangeService"/> <see cref="ITenantChangeService.MoveToDifferentDatabaseAsync"/>
        /// which moves the tenant data to another database and then deletes the the original tenant data.
        /// NOTE: You can change the <see cref="Tenant.HasOwnDb"/> by calling this method with no change to the <see cref="Tenant.DatabaseInfoName"/>.
        /// </summary>
        /// <param name="tenantToMoveId">The primary key of the AuthP tenant to be moved.
        ///     NOTE: If its a hierarchical tenant, then the tenant must be the highest parent.</param>
        /// <param name="hasOwnDb">Says whether the new database will only hold this tenant</param>
        /// <param name="databaseInfoName">This is the name of the database information in the shardingsettings file.</param>
        /// <returns>status</returns>
        public async Task<IStatusGeneric> MoveToDifferentDatabaseAsync(int tenantToMoveId, bool hasOwnDb,
            string databaseInfoName)
        {
            var status = new StatusGenericHandler 
                { Message = $"Successfully moved the tenant to the database defined by the database information with the name '{databaseInfoName}'." };

            if (!_tenantType.IsSharding())
                throw new AuthPermissionsException(
                    "This method can only be called when sharding is turned on.");

            var tenantChangeService = _tenantChangeServiceFactory.GetService();

            await using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                var tenant = await _context.Tenants
                    .SingleOrDefaultAsync(x => x.TenantId == tenantToMoveId);

                if (tenant == null)
                    return status.AddError("Could not find the tenant you were looking for.");

                if (tenant.IsHierarchical && tenant.ParentDataKey != null)
                    return status.AddError("For hierarchical tenants you must provide the top tenant's TenantId, not a child tenant.");

                if (tenant.DatabaseInfoName == databaseInfoName)
                {
                    if (tenant.HasOwnDb == hasOwnDb)
                        return status.AddError("You didn't change any of the sharding parts, so nothing was changed.");

                    status.Message = $"The tenant wasn't moved but its {nameof(Tenant.HasOwnDb)} was changed to {hasOwnDb}.";
                }

                if (status.CombineStatuses(await CheckHasOwnDbIsValidAsync(hasOwnDb, databaseInfoName)).HasErrors)
                    return status;

                var previousDatabaseInfoName = tenant.DatabaseInfoName;
                var previousDataKey = tenant.GetTenantDataKey();
                tenant.UpdateShardingState(databaseInfoName, hasOwnDb);

                if (status.CombineStatuses(await _context.SaveChangesWithChecksAsync()).HasErrors)
                    return status;

                if (previousDatabaseInfoName != databaseInfoName)
                {
                    //Just changes the HasNoDb part
                    var mainError = await tenantChangeService
                        .MoveToDifferentDatabaseAsync(previousDatabaseInfoName, previousDataKey, tenant);
                    if (mainError != null)
                        return status.AddError(mainError);
                }

                if (status.IsValid)
                    await transaction.CommitAsync();
            }
            catch (Exception e)
            {
                if (_logger == null)
                    throw;

                _logger.LogError(e, $"Failed to {e.Message}");
                return status.AddError(
                    "The attempt to move the tenant to another database failed. Please contact the admin team.");
            }

            return status;
        }

        //----------------------------------------------------------
        // private methods

        /// <summary>
        /// If the hasOwnDb is true, it returns an error if any tenants have the same <see cref="Tenant.DatabaseInfoName"/>
        /// </summary>
        /// <param name="hasOwnDb"></param>
        /// <param name="databaseInfoName"></param>
        /// <returns>status</returns>
        private async Task<IStatusGeneric> CheckHasOwnDbIsValidAsync(bool hasOwnDb, string databaseInfoName)
        {
            // Create the Master status
            var status = new StatusGenericHandler();

            // Nothing to do if the tenant doen't have its own db
            if (!hasOwnDb)
                return status;

            // Set the passed databaseInfoName to the default if null
            databaseInfoName ??= _options.ShardingDefaultDatabaseInfoName;

            // Check the db to see if any existing tenant is using the same datanbaseInfoName
            // If so, add and error message to Master status
            if (await _context.Tenants.AnyAsync(x => x.DatabaseInfoName == databaseInfoName))
                status.AddError(
                    $"The {nameof(hasOwnDb)} parameter is true, but the sharding database name " +
                    $"'{databaseInfoName}' already has tenant(s) using that database.");

            return status;
        }

        /// <summary>
        /// This finds the roles with the given names from the AuthP database. Returns errors if not found
        /// NOTE: The Tenant checks that the role's <see cref="RoleToPermissions.RoleType"/> are valid for a tenant
        /// </summary>
        /// <param name="tenantRoleNames">List of role name. Can be null, which means no roles to add</param>
        /// <returns>Status</returns>
        private async Task<IStatusGeneric<List<RoleToPermissions>>> GetRolesWithChecksAsync(
            List<string> tenantRoleNames)
        {
            // Create the Master status
            var status = new StatusGenericHandler<List<RoleToPermissions>>();

            // If the passed tenantRoleNames has members...
            // Query the db and build a list of RoleToPermissions records matching the passed role names
            // Otherwise...return an empty list
            var foundRoles = tenantRoleNames?.Any() == true
                ? await _context.RoleToPermissions
                    .Where(x => tenantRoleNames.Contains(x.RoleName))
                    .Distinct()
                    .ToListAsync()
                : new List<RoleToPermissions>();

            // If a RoleToPermission record was NOT found for each role passed in tenantRoleNames...
            if (foundRoles.Count != (tenantRoleNames?.Count ?? 0))
            {
                // Find the missing roles and add and error message to the Master status
                foreach (var badRoleName in tenantRoleNames.Where(x => !foundRoles.Select(y => y.RoleName).Contains(x)))
                {
                    status.AddError($"The Role '{badRoleName}' was not found in the lists of Roles.");
                }
            }

            // Return the list of RoleToPermissions in the Master status.Result
            return status.SetResult(foundRoles);
        }
    }
}
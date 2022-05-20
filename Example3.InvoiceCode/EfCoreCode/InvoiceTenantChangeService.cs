// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using AuthPermissions.AdminCode;
using AuthPermissions.AdminCode.Services;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.DataLayer.Classes;
using Example3.InvoiceCode.EfCoreClasses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Example3.InvoiceCode.EfCoreCode
{
    public class InvoiceTenantChangeService : ITenantChangeService
    {
        private readonly InvoicesDbContext _context;
        private readonly ILogger _logger;

        /// <summary>
        /// This allows the tenantId of the deleted tenant to be returned.
        /// This is useful if you want to soft delete the data
        /// </summary>
        public int DeletedTenantId { get; private set; }

        public InvoiceTenantChangeService(InvoicesDbContext context, ILogger<InvoiceTenantChangeService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// When a new AuthP Tenant is created, then this method is called. If you have a tenant-type entity in your
        /// application's database, then this allows you to create a new entity for the new tenant.
        /// You should apply multiple changes within a transaction so that if any fails then any previous changes will be rolled back.
        /// NOTE: With hierarchical tenants you cannot be sure that the tenant has, or will have, children
        /// </summary>
        /// <param name="tenant"></param>
        /// <returns>Returns null if all OK, otherwise the create is rolled back and the return string is shown to the user</returns>
        public async Task<string> CreateNewTenantAsync(Tenant tenant)
        {
            // Create a new Company Tenant and save to the db
            var newCompanyTenant = new CompanyTenant
            {
                DataKey = tenant.GetTenantDataKey(),
                AuthPTenantId = tenant.TenantId,
                CompanyName = tenant.TenantFullName
            };
            _context.Add(newCompanyTenant);
            await _context.SaveChangesAsync();

            return null;
        }

        /// <summary>
        /// This is used with single-level tenant to either
        /// a) delete all the application-side data with the given DataKey, or
        /// b) soft-delete the data.
        /// You should apply multiple changes within a transaction so that if any fails then any previous changes will be rolled back
        /// Notes:
        /// - The created application's DbContext won't have a DataKey, so you will need to use IgnoreQueryFilters on any EF Core read
        /// - You can provide information of what you have done by adding public parameters to this class.
        ///   The TenantAdmin <see cref="AuthTenantAdminService.DeleteTenantAsync"/> method returns your class on a successful Delete
        /// </summary>
        /// <param name="tenant"></param>
        /// <returns>Returns null if all OK, otherwise the AuthP part of the delete is rolled back and the return string is shown to the user</returns>
        public async Task<string> SingleTenantDeleteAsync(Tenant tenant)
        {
            await using var transaction = await _context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                // Get the DataKey for the passed tenant
                var dataKey = tenant.GetTenantDataKey();

                // Create/execute the SQL statement to delete all invoice line items
                var deleteSalesSql = $"DELETE FROM invoice.{nameof(InvoicesDbContext.LineItems)} WHERE DataKey = '{dataKey}'";
                await _context.Database.ExecuteSqlRawAsync(deleteSalesSql);

                // // Create/execute the SQL statement to delete all invoices
                var deleteStockSql = $"DELETE FROM invoice.{nameof(InvoicesDbContext.Invoices)} WHERE DataKey = '{dataKey}'";
                await _context.Database.ExecuteSqlRawAsync(deleteStockSql);

                // Get the CompanyTenant for the passed Tenant.Idfrom the db 
                var companyTenant = await _context.Set<CompanyTenant>()

                    // Specifies that the current Entity Framework LINQ query should not have any model-level entity query filters applied.
                    .IgnoreQueryFilters()

                    // Asynchronously returns the only element of a sequence that satisfies a specified
                    //     condition or a default value if no such element exists; this method throws an
                    //     exception if more than one element satisfies the condition.
                    .SingleOrDefaultAsync(x => x.AuthPTenantId == tenant.TenantId);

                // If we found the CompanyTenant, remove it from the db
                // Remember the deleted TenantId in the instance variable
                if (companyTenant != null)
                {
                    _context.Remove(companyTenant);
                    await _context.SaveChangesAsync();
                    DeletedTenantId = tenant.TenantId;
                }

                // Commit all db changes
                await transaction.CommitAsync();
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"Failure when trying to delete the '{tenant.TenantFullName}' tenant.");
                return "There was a system-level problem - see logs for more detail";
            }

            return null;
        }

        /// <summary>
        /// This is called when the name of your Tenants is changed. This is useful if you use the tenant name in your multi-tenant data.
        /// NOTE: The created application's DbContext won't have a DataKey, so you will need to use IgnoreQueryFilters on any EF Core read
        /// </summary>
        /// <param name="tenant"></param>
        /// <returns>Returns null if all OK, otherwise the tenant name is rolled back and the return string is shown to the user</returns>
        public async Task<string> SingleTenantUpdateNameAsync(Tenant tenant)
        {
            // Get the CompanyTenant record for the passed Tenant from the db
            var companyTenant = await _context.Companies

                // Specifies that the current Entity Framework LINQ query should not have any model-level entity query filters applied.
                .IgnoreQueryFilters()

                // Asynchronously returns the only element of a sequence that satisfies a specified
                //     condition or a default value if no such element exists; this method throws an
                //     exception if more than one element satisfies the condition.
                .SingleOrDefaultAsync(x => x.AuthPTenantId == tenant.TenantId);

            // If we found the CompantTenant, change its name and save to the db
            if (companyTenant != null)
            {
                companyTenant.CompanyName = tenant.TenantFullName;
                await _context.SaveChangesAsync();
            }

            return null;
        }


        public Task<string> HierarchicalTenantUpdateNameAsync(List<Tenant> tenantsToUpdate)
        {
            throw new NotImplementedException();
        }

        //Not used
        public Task<string> HierarchicalTenantDeleteAsync(List<Tenant> tenantsInOrder)
        {
            //This example is using single level multi-tenant, so this will never be called.

            throw new NotImplementedException();
        }

        //Not used
        public Task<string> MoveHierarchicalTenantDataAsync(List<(string oldDataKey, Tenant tenantToMove)> tenantToUpdate)
        {
            throw new NotImplementedException();
        }

        public Task<string> MoveToDifferentDatabaseAsync(string oldDatabaseInfoName, string oldDataKey,
            Tenant updatedTenant)
        {
            throw new NotImplementedException();
        }
    }
}
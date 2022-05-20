// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Linq;
using AuthPermissions.BaseCode.CommonCode;
using Microsoft.EntityFrameworkCore;

namespace Example3.InvoiceCode.EfCoreCode
{
    public static class MarkDataKeyExtension
    {
        public static void MarkWithDataKeyIfNeeded(this DbContext context, string accessKey)
        {
            // Interate through the EF graph for entities whose state is Added
            foreach (var entityEntry in context.ChangeTracker.Entries()
                .Where(e => e.State == EntityState.Added))
            {
                // Cast the entity as IDataKeyFilterReadWrite (which the Invoice class has)
                var hasDataKey = entityEntry.Entity as IDataKeyFilterReadWrite;

                // If Entity is not null and its DataKey property is null...
                if (hasDataKey != null && hasDataKey.DataKey == null)
                    // If the entity has a DataKey it will only update it if its null
                    // This allow for the code to define the DataKey on creation
                    hasDataKey.DataKey = accessKey;
            }
        }
    }
}
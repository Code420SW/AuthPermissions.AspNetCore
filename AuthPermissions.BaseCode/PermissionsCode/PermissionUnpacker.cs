// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

namespace AuthPermissions.BaseCode.PermissionsCode
{
    /// <summary>
    /// Holds a extension method to unpack permissions
    /// </summary>
    public static class PermissionUnpacker
    {
        /// <summary>
        /// This takes a string containing packed permissions and returns the names of the Permission member names
        /// </summary>
        /// <param name="packedPermissions"></param>
        /// <param name="permissionsEnumType"></param>
        /// <returns></returns>
        public static List<string> ConvertPackedPermissionToNames(this string packedPermissions, Type permissionsEnumType)
        {
            // Bail if passed packed permissions is null
            if (packedPermissions == null)
                return null;

            // Initialize the list to be returned
            var permissionNames = new List<string>();

            // Iterate through each char in the packed permissions...
            foreach (var permissionChar in packedPermissions)
            {
                // Convert the chat to ushort and match it to the passed enum to get the name of the permission
                var enumName = Enum.GetName(permissionsEnumType, (ushort)permissionChar);

                // Add to list if found
                if (enumName != null)
                    permissionNames.Add(enumName);
            }

            return permissionNames;
        }
    }
}
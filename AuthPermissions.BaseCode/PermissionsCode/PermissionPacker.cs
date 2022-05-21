// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.ComponentModel.DataAnnotations;
using System.Reflection;
using AuthPermissions.BaseCode.CommonCode;


namespace AuthPermissions.BaseCode.PermissionsCode
{
    /// <summary>
    /// This class contains extension methods to pack Permissions names into a unicode string
    /// </summary>
    public static class PermissionPacker
    {
        /// <summary>
        /// Packs permission names found in the comma delimited string into a unicode string
        /// </summary>
        /// <param name="enumPermissionsType"></param>
        /// <param name="permissionNames"></param>
        /// <returns></returns>
        public static string PackCommaDelimitedPermissionsNames(this Type enumPermissionsType, string permissionNames)
        {
            return enumPermissionsType.PackPermissionsNames(permissionNames.Split(',').Select(x => x.Trim()));
        }

        /// <summary>
        /// Packs a list of permissions names into a unicode string
        /// </summary>
        /// <param name="enumPermissionsType"></param>
        /// <param name="permissionNames"></param>
        /// <returns></returns>
        public static string PackPermissionsNames(this Type enumPermissionsType, IEnumerable<string> permissionNames)
        {
            var packedPermissions = permissionNames.Aggregate("", (s, permissionName) =>
                s + (char)Convert.ChangeType(Enum.Parse(enumPermissionsType, permissionName), typeof(char)));
            CheckPackedPermissionsDoesNotContainZeroChar(packedPermissions);
            return packedPermissions;
        }

        /// <summary>
        /// This converts a list of enum permission names into a packed string. If any permission names are bad it calls the reportError action
        /// </summary>
        /// <param name="enumPermissionsType"></param>
        /// <param name="permissionNames"></param>
        /// <param name="reportError">Report a permission name that isn't in the list of enum members</param>
        /// <param name="foundAdvancedPermission">Only called if an advanced permission is found</param>
        /// <returns>the packed permission string</returns>
        public static string PackPermissionsNamesWithValidation(this Type enumPermissionsType,
            IEnumerable<string> permissionNames, Action<string> reportError, Action foundAdvancedPermission)
        {
            var packedPermissions = "";

            // Iterate throght the passed list of permissionNames...
            foreach (var permissionName in permissionNames)
            {
                try
                {
                    // Get the enum value from the enum name
                    Enum.Parse(enumPermissionsType, permissionName);

                    // Determine if this permission has the AutoGenerateFilter Display attribute
                    // If so, call the passed action
                    var displayAttribute =  enumPermissionsType.GetMember(permissionName)[0].GetCustomAttribute<DisplayAttribute>();
                    if (displayAttribute?.GetAutoGenerateFilter() == true)
                        foundAdvancedPermission();
                }
                catch (ArgumentException)
                {
                    // For any error, call the passed reportError action
                    reportError(permissionName);
                    continue;
                }

                // Convert the enum value to a char and add to the string
                packedPermissions +=
                    (char) Convert.ChangeType(Enum.Parse(enumPermissionsType, permissionName), typeof(char));
            }

            // Last error-check for char(0)
            CheckPackedPermissionsDoesNotContainZeroChar(packedPermissions);


            return packedPermissions;
        }

        //----------------------------------------------------------------------
        // private methods

        private static void CheckPackedPermissionsDoesNotContainZeroChar(string packedPermissions)
        {
            if (packedPermissions.Contains((char)0))
                throw new AuthPermissionsBadDataException(
                    "A packed permissions string must not contain a char of zero value");
        }
    }
}
# Release Notes

## 3.2.0

- BREAKING CHANGE: The 3.0.0 sharding didn't work with Azure, so the way to define databases for sharding has changed - see issue #29 and docs: Setup -> Multi tenant configuration -> Sharding database settings
- Improvement: The AuthUserAdmin method called `UpdateUserAsync` now allows you to select which properties you want to update - see docs: Admin -> AuthUser admin.
- Removed: Removed AuthUserAdmin methods 1AddRoleToUser` and `RemoveRoleToUser` as the change to the `UpdateUserAsync` covers this.

## 3.1.0

- New feature: Now supports PostgreSQL database
- NOTE: A lot of namespaces changed to support SqlServer and PostgreSQL

## 3.0.0

- BREAKING CHANGE: The ITenantChangeService has changed to allow multi-tenant sharding to be added - see the UpdateToVersion2.md file for more info
- BREAKING CHANGE: The option called AppConnectionString has been removed. Its longer needed because of ITenantChangeService change
- Changes to the AuthP database which contains a non-breaking migration. This will be automatically added on startup. 
- New Feature: Adding optional sharding to either a single-level or hierarchical multi-tenant applications - see documentation for an article explaining how to setup sharding
- New Feature: You can mark an AuthUser as disabled, which means no AuthP claims will be added to the user's claims.


## 2.3.1

- Bug Fix: Problem in ClaimCalculator when used with multi-tenant applications - see issue #23 

## 2.3.0

- New Feature: You can add extra claims to the user via the RegisterAddClaimToUser method
- New Feature: Tap into AuthPermissionsDbContext events by registering a service implmenting the IRegisterStateChangeEvent interface
- Bug Fix: UpdateRoleToPermissionsAsync now return errors if a Role change is invalid for a user or tenants that is that Role - see issue #13
- Bug Fix: DeleteRoleAsync now handles tenant Roles - see issue #13
- Bug Fix: Add or update of an AuthUser now checks the tenant has the correct Roles - see issue #15

## 2.2.0

- New Feature: Added "Access the data of other tenant" feature - see issue #10

## 2.1.0

- Bug fix: Fixed a bug when creating a tenant that had tenant roles
- BREAKING CHANGE: GetAllRoleNamesAsync is now called GetRoleNamesForUsersAsync and takes the UserId
- New Feature: Added GetRoleNamesForTenantsAsync to AuthTenantAdminService
- Minor change: The UpdateRoleToPermissionsAsync method now allows you to change the RoleType


## 2.0.0

- BREAKING CHANGE: The SetupAspNetCoreAndDatabase configuration method uses a different approach that supports multiple instances of your app
- BREAKING CHANGE: Changes the bulk loading of role and tenants to support the new multi-tenant Roles feature
- BREAKING CHANGE: Updated to net6.0 only
- MULTI-TENANT BREAKING CHANGE: The DataKey format has changed, You need to migrate your application - see issue 
- MULTI-TENANT BREAKING CHANGE: The RoleAdmin method QueryRoleToPermissions now needs the logged-in userId in multi-tenant applications
- New features: Each multi-tenant can have a different version, e.g. Free, Pro, Enterprise -  see issue #9
- New features: A Tenant Admin user can't see "Advanced Roles", i.e. Role that only an App Admin user should use - see issue #9
- New features: Uses Net.RunMethodsSequentially library to handle startup migrate / seed of databases for applications have multiple instances running

## 1.4.0

New Feature: Added IndividualAccountsAuthentication<TCustomIdentityUser> and AddSuperUserToIndividualAccounts<TCustomIdentityUser> to handle Individual Accounts provider with a custom IdentityUser. See https://github.com/JonPSmith/AuthPermissions.AspNetCore/wiki/Setup-Authentication for more info.


## 1.3.0

- BREAKING CHANGE: When registering AuthP you need to state what authentication provider you are using - see https://github.com/JonPSmith/AuthPermissions.AspNetCore/wiki/Authentication-explained
- New Feature: New AzureAdAuthentication method that causes an Azure AD via Login will add AuthP claims to the user. See Example5 for for how this works.


## 1.2.1

- Bug fix: UpdateUserAsync didn't handle no roles properly
- Change: UpdateUserAsync method parameter roleNames cannot be null

## 1.2.0

- BREAKING CHANGE: Different AuthTenantAdminService to be more useful
- New Feature: Added ITenantChangeService to apply tenant changes to application DbContext
- Updated Microsoft's NuGets to fix a security issue in example2

## 1.1.0

- BREAKING CHANGE: Different AuthRolesAdminService to be more useful
- BREAKING CHANGE: Different AuthUsersAdminService to be more useful
- Improvements to the Example AuthUsersController and RolesController
- BUG: Fixed bug in Example4 "sync users" feature
- BUG: Fixed bug in using in-memory database in an application

## 1.0.0-preview001

- Preview version - looking for feedback.





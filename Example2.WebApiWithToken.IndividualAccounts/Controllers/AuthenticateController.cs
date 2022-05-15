using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using AuthPermissions;
using AuthPermissions.AspNetCore.JwtTokenCode;
using AuthPermissions.AspNetCore.Services;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.PermissionsCode;
using Example2.WebApiWithToken.IndividualAccounts.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Example2.WebApiWithToken.IndividualAccounts.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ITokenBuilder _tokenBuilder;

        public AuthenticateController(SignInManager<IdentityUser> signInManager,
                                      UserManager<IdentityUser> userManager,
                                      ITokenBuilder tokenBuilder,
                                      IClaimsCalculator claimsCalculator)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenBuilder = tokenBuilder;
        }

        /// <summary>
        /// This checks you are a valid user and returns a JTW token
        /// </summary>
        /// <param name="loginUser"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("authenticate")]
        public async Task<ActionResult> Authenticate(LoginUserModel loginUser)
        {
            // The LoginUserMode comes from Example2.WebApiWithToken.IndividualAccounts.Models

            // Attempts to sign in the specified userName and password combination as an asynchronous
            //  operation.
            //NOTE: The _signInManager.PasswordSignInAsync does not change the current ClaimsPrincipal - that only happens on the next access with the token
            var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, false);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Username or password is incorrect" });
            }

            //
            //  Gets the user, if any, associated with the normalized value of the specified
            //     email address. Note: Its recommended that identityOptions.User.RequireUniqueEmail
            //     be set to true when using this method, otherwise the store may throw if there
            //     are users with duplicate emails.
            //
            var user = await _userManager.FindByEmailAsync(loginUser.Email);

            //
            // This generates a JWT token containing the claims from the AuthPermissions database
            // and a Refresh token to go with this token
            //
            return Ok(await _tokenBuilder.GenerateJwtTokenAsync(user.Id));
        }

        /// <summary>
        /// DEMO ONLY: This will generate a JWT token for the user "Super@g1.com"
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("quickauthenticate")]
        public async Task<ActionResult> QuickAuthenticate()
        {
            // Trigger the authenticate action with a predefined LoginUserModel
            return await Authenticate(new LoginUserModel {Email = "Super@g1.com", Password = "Super@g1.com"});
        }

        /// <summary>
        /// This checks you are a valid user and returns a JTW token and a Refresh token
        /// </summary>
        /// <param name="loginUser"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("authenticatewithrefresh")]
        public async Task<ActionResult<TokenAndRefreshToken>> AuthenticateWithRefresh(LoginUserModel loginUser)
        {

            // The LoginUserMode comes from Example2.WebApiWithToken.IndividualAccounts.Models

            // Attempts to sign in the specified userName and password combination as an asynchronous
            //  operation.
            //NOTE: The _signInManager.PasswordSignInAsync does not change the current ClaimsPrincipal - that only happens on the next access with the token
            var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, false);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Username or password is incorrect" });
            }

            //
            //  Gets the user, if any, associated with the normalized value of the specified
            //     email address. Note: Its recommended that identityOptions.User.RequireUniqueEmail
            //     be set to true when using this method, otherwise the store may throw if there
            //     are users with duplicate emails.
            //
            var user = await _userManager.FindByEmailAsync(loginUser.Email);

            //
            // This generates a JWT token containing the claims from the AuthPermissions database
            // and a Refresh token to go with this token
            //
            return Ok(await _tokenBuilder.GenerateTokenAndRefreshTokenAsync(user.Id));
        }

        /// <summary>
        /// DEMO ONLY: This will generate a JWT token and a Refresh token for the user "Super@g1.com"
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("quickauthenticatewithrefresh")]
        public Task<ActionResult<TokenAndRefreshToken>> QuickAuthenticateWithRefresh()
        {
            // Trigger the authenticatewithrefresh action with a predefined LoginUserModel
            return AuthenticateWithRefresh(new LoginUserModel {Email = "Super@g1.com", Password = "Super@g1.com"});
        }

        /// <summary>
        /// This will refresh the JWT token using the provided Refresh token
        /// </summary>
        /// <param name="tokenAndRefresh"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("refreshauthentication")]
        public async Task<ActionResult<TokenAndRefreshToken>> RefreshAuthentication(TokenAndRefreshToken tokenAndRefresh)
        {
            // This will refresh the JWT token if the JWT is valid(but can be expired) and the RefreshToken in the database is valid
           var result = await _tokenBuilder.RefreshTokenUsingRefreshTokenAsync(tokenAndRefresh);

            // If the Token and RefreshToken were successfuly renewed, return them
            if (result.updatedTokens != null)
                return result.updatedTokens;

            // Otherwise return some sort of error code
            return StatusCode(result.HttpStatusCode);
        }

        /// <summary>
        /// This will mark the JST refresh as used, so the user cannot refresh the JWT Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("logout")]
        public async Task<ActionResult> Logout([FromServices]IDisableJwtRefreshToken service)
        {
            // This returns the UserId from the current user's Claims
            var userId = User.GetUserIdFromUser();

            // This will mark the latest, valid RefreshToken as invalid.
            // Call this a) when a user logs out, or b) you want to log out an active user when the JTW times out
            await service.MarkJwtRefreshTokenAsUsedAsync(userId);

            return Ok();
        }

        /// <summary>
        /// This returns the permission names for the current user (or null if not available)
        /// This can be useful for your front-end to use the current user's Permissions to only expose links
        /// that the user has access too.
        /// You should call this after a login and when the JWT Token is refreshed
        /// </summary>
        /// <param name="service"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("getuserpermissions")]
        public ActionResult<List<string>> GetUsersPermissions([FromServices] IUsersPermissionsService service)
        {
            return service.PermissionsFromUser(User);
        }

    }
}

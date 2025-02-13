using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Threading.Tasks;
using AuthPermissions;
using AuthPermissions.AspNetCore;
using AuthPermissions.AspNetCore.Services;
using Example2.WebApiWithToken.IndividualAccounts.Data;
using Example2.WebApiWithToken.IndividualAccounts.Models;
using Example2.WebApiWithToken.IndividualAccounts.PermissionsCode;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RunMethodsSequentially;
using AuthPermissions.AspNetCore.StartupServices;
using AuthPermissions.BaseCode;

namespace Example2.WebApiWithToken.IndividualAccounts
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration.GetConnectionString("DefaultConnection");

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

            services.AddDefaultIdentity<IdentityUser>(
                    options => options.SignIn.RequireConfirmedAccount = false)
                .AddEntityFrameworkStores<ApplicationDbContext>();


            // Configure Authentication using JWT token with refresh capability
            JwtSetupData jwtData = new();
            Configuration.Bind("JwtData", jwtData);

            services.AddAuthentication(auth =>
                {
                    auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    auth.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                })

                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = jwtData.Issuer,
                        ValidateAudience = true,
                        ValidAudience = jwtData.Audience,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtData.SigningKey)),
                        ClockSkew = TimeSpan.Zero //The default is 5 minutes, but we want a quick expires for JTW refresh
                    };

                    //This code came from https://www.blinkingcaret.com/2018/05/30/refresh-tokens-in-asp-net-core-web-api/
                    //It returns a useful header if the JWT Token has expired
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            {
                                context.Response.Headers.Add("Token-Expired", "true");
                            }
                            return Task.CompletedTask;
                        }
                    };
                });

            services.RegisterAuthPermissions<Example2Permissions>( options =>
                {
                    //This tells AuthP that you don't have multiple instances of your app running,
                    //so it can run the startup services without a global lock
                    options.UseLocksToUpdateGlobalResources = false;

                    //This sets up the JWT Token. The config is suitable for using the Refresh Token with your JWT Token
                    options.ConfigureAuthPJwtToken = new AuthPJwtConfiguration
                    {
                        Issuer = jwtData.Issuer,
                        Audience = jwtData.Audience,
                        SigningKey = jwtData.SigningKey,
                        //TokenExpires = new TimeSpan(0,5,0), //Quick Token expiration because we use a refresh token
                        TokenExpires = new TimeSpan(0, 1, 0),
                        RefreshTokenExpires = new TimeSpan(1,0,0,0) //Refresh token is valid for one day
                    };
                })
                .UsingEfCoreSqlServer(connectionString) //NOTE: This uses the same database as the individual accounts DB
                .IndividualAccountsAuthentication()
                .AddSuperUserToIndividualAccounts()
                .RegisterFindUserInfoService<IndividualAccountUserLookup>()
                .AddRolesPermissionsIfEmpty(AppAuthSetupData.RolesDefinition)
                .AddAuthUsersIfEmpty(AppAuthSetupData.UsersRolesDefinition)
                .SetupAspNetCoreAndDatabase(options =>
                {
                    //Migrate individual account database
                    options.RegisterServiceToRunInJob<StartupServiceMigrateAnyDbContext<ApplicationDbContext>>();
                    //Add demo users to the database
                    options.RegisterServiceToRunInJob<StartupServicesIndividualAccountsAddDemoUsers>();
                });

            services.AddControllers();

            //thanks to: https://www.c-sharpcorner.com/article/authentication-and-authorization-in-asp-net-5-with-jwt-and-swagger/
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Example2.WebApiWithToken.IndividualAccounts", Version = "v1" });

                var securitySchema = new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                };

                c.AddSecurityDefinition("Bearer", securitySchema);

                var securityRequirement = new OpenApiSecurityRequirement
                {
                    { securitySchema, new[] { "Bearer" } }
                };

                c.AddSecurityRequirement(securityRequirement);
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Example2.WebApiWithToken.IndividualAccounts v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

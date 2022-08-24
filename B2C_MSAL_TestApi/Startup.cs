using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace B2C_MSAL_TestApi
{
    public class Startup
    {
        private static string CORS_POLICY_NAME = "Allow_React_App";
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApi(options =>
                {
                    Configuration.Bind("Authz", options);

                    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            $"https://login.microsoftonline.com/9f5749d2-1a60-4dbd-981c-ae949f54a23d/.well-known/openid-configuration",
                            new OpenIdConnectConfigurationRetriever());

                    var config = configManager.GetConfigurationAsync().GetAwaiter().GetResult();

                    options.TokenValidationParameters.NameClaimType = "name";

                    options.TokenValidationParameters.ValidateLifetime = true;
                    options.TokenValidationParameters.ValidateAudience = true;
                    options.TokenValidationParameters.ValidateIssuer = true;
                    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                    options.TokenValidationParameters.ValidateTokenReplay = true;

                    options.TokenValidationParameters.ValidIssuer = config.Issuer;
                    options.TokenValidationParameters.IssuerSigningKeys = config.SigningKeys;
                },

            options => { Configuration.Bind("Authz", options); });

            services.AddCors(options =>
            {
                options.AddPolicy(
                    name: CORS_POLICY_NAME,
                    policy =>
                    {
                        policy
                            .WithOrigins(
                                "http://localhost:3000",
                                "https://thankful-forest-09c977103.1.azurestaticapps.net"
                            )
                            .WithHeaders("Authorization")
                            .WithMethods("GET");
                    });
            });

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                IdentityModelEventSource.ShowPII = true;
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();


            app.UseAuthentication();
            app.UseAuthorization();

            app.UseCors(CORS_POLICY_NAME);

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

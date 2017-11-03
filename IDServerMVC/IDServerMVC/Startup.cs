using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using IdentityServer3.Core.Configuration;
using IDServerMVC.IdentityServer;
using IdentityServer3.Core.Models;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web.Helpers;
using System.IdentityModel.Tokens;
using IdentityServer3.Core;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Owin.Security;
using Kentor.AuthServices.Owin;
using Kentor.AuthServices.Configuration;
using System.IdentityModel.Metadata;
using Kentor.AuthServices;

[assembly: OwinStartup(typeof(IDServerMVC.Startup))]

namespace IDServerMVC
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(new IdentityServerOptions
                {
                    SiteName = "Embedded IdentityServer",
                    SigningCertificate = LoadCertificate(),

                    Factory = new IdentityServerServiceFactory()
                                .UseInMemoryUsers(Users.Get())
                                .UseInMemoryClients(Clients.Get())
                                .UseInMemoryScopes(Scopes.Get()),
                    AuthenticationOptions=new IdentityServer3.Core.Configuration.AuthenticationOptions
                    {
                            EnablePostSignOutAutoRedirect = true,
                        IdentityProviders= ConfigureIdentityProviders,CookieOptions=new IdentityServer3.Core.Configuration.CookieOptions()
                    }
                });
            });
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "https://localhost:44359/identity",
                ClientId = "0oaclr9tmf2WIwZ3N0h7",
                Scope = "openid profile roles",
                RedirectUri = "https://localhost:44359/",
                ResponseType = "id_token",

                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = n =>
                    {
                        var id = n.AuthenticationTicket.Identity;

                        // we want to keep first name, last name, subject and roles
                        var givenName = id.FindFirst(Constants.ClaimTypes.GivenName);
                        var familyName = id.FindFirst(Constants.ClaimTypes.FamilyName);
                        var sub = id.FindFirst(Constants.ClaimTypes.Subject);
                        var roles = id.FindAll(Constants.ClaimTypes.Role);

                        // create new identity and set name and role claim type
                        var nid = new ClaimsIdentity(
                            id.AuthenticationType,
                            Constants.ClaimTypes.GivenName,
                            Constants.ClaimTypes.Role);

                        nid.AddClaim(givenName);
                        nid.AddClaim(familyName);
                        nid.AddClaim(sub);
                        nid.AddClaims(roles);

                        // add some other app specific claim
                        nid.AddClaim(new Claim("app_specific", "some data"));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            nid,
                            n.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    }
                }
                });
            app.UseResourceAuthorization(new AuthorizationManager());
            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
        }
        public static void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            var authServicesOptions = new KentorAuthServicesAuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    AuthenticateRequestSigningBehavior = SigningBehavior.Never ,// or add a signing certificate
                    EntityId = new EntityId("https://dev-450271.oktapreview.com/app/adev450271_embeddedidentityserver_1/exkcmjd8l0cL6eiGN0h7/sso/saml") ,
                    ReturnUrl=new Uri("https://localhost:44359/Home/Userconfig"),// from (B) above
               //     WantAssertionsSigned=true
                },
                SignInAsAuthenticationType = signInAsType,
                AuthenticationType = "okta", // this is the "idp" - identity provider - that you can refer to throughout identity server
                Caption = "Okta",  // this is the caption for the button or option that a user might see to prompt them for this login option  
            };
            
            authServicesOptions.IdentityProviders.Add(new IdentityProvider(
                new EntityId("http://www.okta.com/exkcmjd8l0cL6eiGN0h7"), authServicesOptions.SPOptions)  // from (F) above
            {
                LoadMetadata = true,
                MetadataLocation = ("https://dev-450271.oktapreview.com/app/exkcmjd8l0cL6eiGN0h7/sso/saml/metadata") ,// see Metadata note above
               // AllowUnsolicitedAuthnResponse=true,
               
            });
            app.UseKentorAuthServicesAuthentication(authServicesOptions);
        }
        X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(//System.IO.File.ReadAllBytes(string.Format(@"{0}\bin\identityServer\okta.cert", AppDomain.CurrentDomain.BaseDirectory)));
              string.Format(@"{0}\bin\identityServer\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }
    }
}

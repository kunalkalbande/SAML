using Kentor.AuthServices;
using Kentor.AuthServices.Saml2P;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using System.Xml.Linq;
using Thinktecture.IdentityModel.Client;
using Thinktecture.IdentityModel.Mvc;
using static IdentityServer3.Core.Constants;

namespace IDServerMVC.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        [HandleForbidden]
        public ActionResult About()
        {
            return View((User as ClaimsPrincipal).Claims);
        }
      //  [ResourceAuthorize("Read", "ContactDetails")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        [ResourceAuthorize("Write", "ContactDetails")]
        [HandleForbidden]
        public ActionResult ContactDetails()
        {
            ViewBag.Message = "Update your contact details!";

            return View();
        }
        public ActionResult Logout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }

        public ActionResult UserConfig()
        {
            var requestId = "";
            string rawSamlData = Request["SAMLResponse"];
           var q= HttpUtility.ParseQueryString(Request.UrlReferrer.Query)["SAMLRequest"];
            byte[] samlrData = Convert.FromBase64String(q);

            // read back into a UTF string
            string samlrAssertion = Encoding.UTF8.GetString(samlrData);
            // Check if the data sent is already encoded, if not results in double encoding
            if (rawSamlData.Contains('%'))
            {
                rawSamlData = HttpUtility.UrlDecode(rawSamlData);
            }

            // read the base64 encoded bytes
            byte[] samlData = Convert.FromBase64String(rawSamlData);

            // read back into a UTF string
            string samlAssertion = Encoding.UTF8.GetString(samlData);
            var xmlDocument = XmlHelpers.XmlDocumentFromString(samlAssertion);
            var xmlElement = xmlDocument.DocumentElement;
            XNamespace pr =  "urn:oasis:names:tc:SAML:2.0:protocol";
            XNamespace ast = "urn:oasis:names:tc:SAML:2.0:assertion";
            requestId = xmlElement.Attributes["InResponseTo"].Value;

            var response = Saml2Response.Read(samlAssertion,new Saml2Id(requestId));

            //var ele=response.XmlElement.LastChild.LastChild;


            XmlReader reader = new XmlNodeReader(xmlDocument);
            XDocument docResp = XDocument.Load(reader);
            //List<SecurityToken> tokens = new List<SecurityToken>();
            //tokens.Add(new X509SecurityToken(new X509Certificate2(System.IO.File.ReadAllBytes(string.Format(@"{0}\bin\identityServer\okta.cert", AppDomain.CurrentDomain.BaseDirectory)))));

            //SecurityTokenResolver outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(new ReadOnlyCollection<SecurityToken>(tokens), true);
            //SecurityToken securityToken = WSSecurityTokenSerializer.DefaultInstance.ReadToken(reader, outOfBandTokenResolver);

            //SamlSecurityToken deserializedSaml = securityToken as SamlSecurityToken;


            XElement attStatement = docResp.Element(pr + "Response").Element(ast + "Assertion").Element(ast + "AttributeStatement");
            string surname = (string)attStatement.Elements(ast + "Attribute").First(a => a.Attribute("Name").Value == "LastName").Element(ast + "AttributeValue");
            string firstname = (string)attStatement.Elements(ast + "Attribute").First(a => a.Attribute("Name").Value == "FirstName").Element(ast + "AttributeValue");
            string email = (string)attStatement.Elements(ast + "Attribute").First(a => a.Attribute("Name").Value == "Email").Element(ast + "AttributeValue");

            List<Claim> c = new List<Claim>();
            c.Add(new Claim("FirstName", firstname));
            c.Add(new Claim("LastName", surname));
            c.Add(new Claim("Email", email));
            return View(c);
        }

        public ActionResult RedirectOkta()
        {
              var x= ((User as ClaimsPrincipal).Claims);
            var idp = "okta";// Request.QueryString["idp"];
            if (string.IsNullOrEmpty(idp))
                throw new Exception("No idp included in redirect querystring!!");

            var scopesForAuth = StandardScopes.OpenId+' '+StandardScopes.AllClaims;
            var state = Guid.NewGuid().ToString("N");
            var nonce = Guid.NewGuid().ToString("N");
            var client = new OAuth2Client(new Uri("https://localhost:44359/identity" + "/connect/Userinfo"));

            var returnUrlForOkta = client.CreateAuthorizeUrl("mvc", "id_token", scopesForAuth,
                ("https://localhost:44359/"),
                state, nonce, acrValues: string.Format("idp:{0}", idp), responseMode: "form_post");

            return null;
        }
    }
}
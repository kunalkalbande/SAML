using Kentor.AuthServices.Saml2P;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Thinktecture.IdentityModel.Client;
using static IdentityServer3.Core.Constants;

namespace IDServerMVC
{
    public partial class Idp_InitiatedRedirect : System.Web.UI.Page
    {
        protected  void Page_Load(object sender, EventArgs e)
        {
            //   var x= ((User as ClaimsPrincipal).Claims);
            string rawSamlData = Request["SAMLResponse"];

            // Check if the data sent is already encoded, if not results in double encoding
            if (rawSamlData.Contains('%'))
            {
                rawSamlData = HttpUtility.UrlDecode(rawSamlData);
            }

            // read the base64 encoded bytes
            byte[] samlData = Convert.FromBase64String(rawSamlData);

            // read back into a UTF string
            string samlAssertion = Encoding.UTF8.GetString(samlData);
           var response= Saml2Response.Read(samlAssertion);
       // var x=    Saml2AuthenticationRequest.Read(samlAssertion, null);
            var iden = Request.LogonUserIdentity;
            var idp = Request.QueryString["idp"];
            if (string.IsNullOrEmpty(idp))
                throw new Exception("No idp included in redirect querystring!!");

            var scopesForAuth = StandardScopes.OpenId+' '+StandardScopes.Profile;
            var state = Guid.NewGuid().ToString("N");
            var nonce = Guid.NewGuid().ToString("N");
            var client = new OAuth2Client(new Uri("https://dev-450271.oktapreview.com/oauth2/v1/authorize" ));

            var returnUrlForOkta = client.CreateAuthorizeUrl("0oaclr9tmf2WIwZ3N0h7", "id_token", scopesForAuth,
                ("https://localhost:44359/Home/UserConfig"),
                state, nonce, acrValues: string.Format("idp:{0}", idp));
         
          
                Response.Redirect(returnUrlForOkta,false);
        }
    }
}
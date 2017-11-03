using IdentityServer3.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace IDServerMVC.IdentityServer
{
    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {
            new Client
            {
                Enabled = true,
                ClientName = "MVC Client",
                ClientId = "0oaclr9tmf2WIwZ3N0h7",
                Flow = Flows.Implicit,

                RedirectUris = new List<string>
                {
                    "https://localhost:44359/"
                },
                PostLogoutRedirectUris =new List<string>
                {
                    "https://localhost:44359/"

                },
                AllowAccessToAllScopes = true
            }
        };
        }
    }
}
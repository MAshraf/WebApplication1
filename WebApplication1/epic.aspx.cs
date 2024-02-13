using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;
using WebApplication1.Models;

namespace WebApplication1
{
    public partial class epic : System.Web.UI.Page
    {
        string pid = "";

        protected void Page_Load(object sender, EventArgs e)
        {
            lblDOB.Text = "dob=" + Request.Params["dob"];
            lblUser.Text = "user=" + Request.Params["user"];

            pid = Request.Params["pid"];

            lblPatient.Text = "pid=" + pid;

            var tok = GetAccessToken();

            var ac = ExtractAccessToken(tok);

            GetInsuID(ac);
        }


        private void GetInsuID(string token)
        {
            var coverage = MakeApiRequest("https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/coverage?patient=" + pid, token);


            lblPlans.Text = " Plans =";
            foreach (var p in ExtractInsurancePlans(coverage))
            {
                lblPlans.Text += p.ID + " " + p.Name + " ,";
            }
        }
         

        private IEnumerable<InsurancePlan1> ExtractInsurancePlans(string xml)
        {
            var parser = new FhirXmlParser();
            Bundle bundle = parser.Parse<Bundle>(xml);

            var plans = bundle.Entry
                .Where(entry => entry.Resource is Coverage)
                .Select(entry => entry.Resource as Coverage)
                .Select(coverage => new InsurancePlan1
                {
                    ID = coverage.Identifier.FirstOrDefault()?.Value,
                    Name = coverage.Payor.FirstOrDefault()?.Display,
                });

            return plans;
        }

        private string GetJwtToken()
        {
            string certificateFilePath = @"D:\temp\Sel Cert\cert2.pfx";
            string certificatePassword = "pass";

            var certificate = new X509Certificate2(certificateFilePath, certificatePassword);

            var claims = new[]
            {
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Iss, "eddd1a93-3763-4ee8-9bb8-dd0bf1e2ea6b"),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Sub, "eddd1a93-3763-4ee8-9bb8-dd0bf1e2ea6b"),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
             new System.Security.Claims.Claim(JwtRegisteredClaimNames.Aud, "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token")
            };

            var rsa = (RSACryptoServiceProvider)certificate.PrivateKey;

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(4), // Token expiration time
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha384Signature)

            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }

        private string GetAccessToken()
        {
            var tokenData = "";
            using (HttpClient client = new HttpClient())
            {
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion", GetJwtToken()),
            });

                var tokenResponse = client.PostAsync($"https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token", tokenRequest)
                                   .ConfigureAwait(false)
                                   .GetAwaiter()
                                   .GetResult();

                tokenData = tokenResponse.Content.ReadAsStringAsync()
                                           .ConfigureAwait(false)
                                           .GetAwaiter()
                                           .GetResult();
            }

            return tokenData;
        }

        private string ExtractAccessToken(string json)
        {
            var serializer = new JavaScriptSerializer();
            var tokenResponse = serializer.Deserialize<dynamic>(json);

            string accessToken = tokenResponse["access_token"];

            return accessToken;
        }

        private string MakeApiRequest(string apiUrl, string accessToken)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");

                var apiResponse = client.GetAsync(apiUrl)
                                            .ConfigureAwait(false)
                                           .GetAwaiter()
                                           .GetResult();
                return apiResponse.Content.ReadAsStringAsync()
                                           .ConfigureAwait(false)
                                           .GetAwaiter()
                                           .GetResult();
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security.Tokens;
using System.Security.Principal;
using Owin;
using Microsoft.Owin;
using log4net;
using AppFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace JwtAuthForWebAPI
{

    public class JwtAuthenticationOwinMiddleware
    {
        private readonly ILog _logger = LogManager.GetLogger("JwtAuthForWebAPI");

        readonly AppFunc next;

        /// <summary>
        ///     Gets or sets a list of audience values (usually URLs, but really just an arbitrary string) that
        ///     will be used during validation of incoming JWTs. At least one value in this list must match
        ///     the AppliesToAddress value on the token.
        /// </summary>
        public IEnumerable<string> AllowedAudiences { get; set; }

        /// <summary>
        ///     Gets or sets the token to use to verify the signature of incoming JWTs.
        /// </summary>
        public SecurityToken SigningToken { get; set; }

        /// <summary>
        ///     Gets or sets the issuer (usually a URL, but really just an arbitrary string) that
        ///     will be used during validation of incoming JWTs. This value must match the TokenIssuerName
        ///     value on the token. Default value is "self".
        /// </summary>
        public string Issuer { get; set; }

        public JwtAuthenticationOwinMiddleware(AppFunc next, IEnumerable<string> AllowedAudiences, string Issuer, SecurityToken SigningToken)
        {
            this.next = next;
            this.AllowedAudiences = AllowedAudiences;
            this.Issuer = Issuer;
            this.SigningToken = SigningToken;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
            IPrincipal principal = null;
            IOwinContext context = new OwinContext(environment);
            var tokenString = GetTokenStringFromHeader(context.Request);

            if (string.IsNullOrEmpty(tokenString))
            {
                _logger.Debug("Token not found in authorization header or request cookie");
                return this.next(environment);
            }

            IJwtSecurityToken token;
            try
            {
                token = CreateToken(tokenString);
            }
            catch (Exception ex)
            {
                _logger.WarnFormat("Error converting token string to JWT: {0}", ex);
                return this.next(environment);
            }

            if (SigningToken != null && token.SignatureAlgorithm != null)
            {
                if (token.SignatureAlgorithm.StartsWith("RS") && !(SigningToken is X509SecurityToken))
                {
                    _logger.DebugFormat("Incoming token signature is X509, but token handler's signing token is not.");
                    return this.next(environment);
                }

                if (token.SignatureAlgorithm.StartsWith("HS") && !(SigningToken is BinarySecretSecurityToken))
                {
                    _logger.DebugFormat("Incoming token signature is SHA, but token handler's signing token is not.");
                    return this.next(environment);
                }
            }

            var parameters = new TokenValidationParameters
            {
                IssuerSigningToken = SigningToken,
                ValidIssuer = Issuer,
                ValidAudiences = AllowedAudiences
            };

            try{

                var tokenHandler = CreateTokenHandler();
                principal = tokenHandler.ValidateToken(token, parameters);

                //if (PrincipalTransformer != null)
                //{
                //    principal = PrincipalTransformer.Transform((ClaimsPrincipal)principal);
                //    CheckPrincipal(principal, PrincipalTransformer.GetType());
                //}

                //Thread.CurrentPrincipal = principal;
                //_logger.DebugFormat("Thread principal set with identity '{0}'", principal.Identity.Name);

                //if (HttpContext.Current != null)
                //{
                //    HttpContext.Current.User = principal;
                //}

            }
            catch (SecurityTokenExpiredException e)
            {
                _logger.ErrorFormat("Security token expired: {0}", e);

                context.Response.StatusCode = 440;
                return context.Response.WriteAsync("Security token expired exception");
            }
            catch (SecurityTokenSignatureKeyNotFoundException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                context.Response.StatusCode = 401;
                return context.Response.WriteAsync("Untrusted signing cert");
            }
            catch (SecurityTokenInvalidAudienceException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                context.Response.StatusCode = 401;
                return context.Response.WriteAsync("Invalid token audience");
            }
            catch (SecurityTokenValidationException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                context.Response.StatusCode = 401;
                return context.Response.WriteAsync("Invalid token");
            }
            catch (SignatureVerificationFailedException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                context.Response.StatusCode = 401;
                return context.Response.WriteAsync("Invalid token signature");
            }
            catch (Exception e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);
                throw;
            }

            context.Request.User = principal;

            return this.next(environment);

        }

        protected string GetTokenStringFromHeader(IOwinRequest request)
        {
            string authHeader = null;
            //if (request.Headers.ContainsKey("Authorization"))
            //{
            authHeader = request.Headers.Get("Authorization");
            //}

            var authParts = authHeader.Split(' ');
            var scheme = authParts[0];
            var tokenString = authParts[1];

            if (scheme == "Bearer")
            {
                return tokenString;
            }
            else
            {
                return null;
            }
        }

        protected virtual IJwtSecurityToken CreateToken(string tokenString)
        {
            return new JwtSecurityTokenAdapter(tokenString);
        }

        protected virtual IJwtSecurityTokenHandler CreateTokenHandler()
        {
            return new JwtSecurityTokenHandlerAdapter();
        }

    }

    public static class AppBuilderJwtAuthenticationOwinMiddlewareExtensions
    {
        /// <summary>
        /// Use JwtAuthenticationOwinMiddleware.
        /// </summary>
        /// <param name="app">Owin app.</param>
        /// <param name="AllowedAudiences">AllowedAudiences.</param>
        /// <param name="Issuer">Issuer.</param>
        /// <param name="SigningToken">SigningToken.</param>
        /// <returns></returns>
        public static IAppBuilder UseJwtAuthentication(this IAppBuilder app, IEnumerable<string> AllowedAudiences, string Issuer, SecurityToken SigningToken)
        {
            return app.Use(typeof(JwtAuthenticationOwinMiddleware), AllowedAudiences, Issuer, SigningToken);
        }
    }
}

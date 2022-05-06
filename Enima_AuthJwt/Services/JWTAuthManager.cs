using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace Enima_AuthJwt
{
    public interface IJWTAuthManager
    {
        AuthResponse Authenticate(string username, string password);
        AuthResponse Refresh(RefreshCred refreshCred);
    }
    public class JWTAuthManager : IJWTAuthManager
    {
        

   

        private readonly string tokenKey;
        private readonly byte[] key;

        public JWTAuthManager(string tokenKey   )
        {
            this.tokenKey = tokenKey;
            this.key = Encoding.ASCII.GetBytes(tokenKey);

        }
 
        public AuthResponse Authenticate(string username, string password)
        {
            if (!DataManager.users.Any(u => u.Key == username && u.Value == password))
            {
                return null;
            }

            var token = GenerateTokenString(username);
            var refreshToken = GenerateRefreshToken();

            if (DataManager.UsersRefreshTokens.ContainsKey(username))
            {
                DataManager.UsersRefreshTokens[username] = refreshToken;
            }
            else
            {
                DataManager.UsersRefreshTokens.Add(username, refreshToken);
            }

            return new AuthResponse
            {
                JwtToken = token,
                RefreshToken = refreshToken
            };
        }


        public AuthResponse Refresh(RefreshCred refreshCred)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;

            var pricipal = tokenHandler.ValidateToken(
                refreshCred.JwtToken,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
                },
                out validatedToken);

            var jwtToken = validatedToken as JwtSecurityToken;

            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token passed!");
            }

            var userName = pricipal.Identity.Name ;
            if (refreshCred.RefreshToken != DataManager.UsersRefreshTokens[userName])
            {
                throw new SecurityTokenException("Invalid token passed!");
            }

            return new AuthResponse
            {
                JwtToken = this.GenerateTokenString(userName ),
                RefreshToken = refreshCred.RefreshToken
            };
          
        }

        string GenerateTokenString(string username,   Claim[] claims = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(tokenKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                 claims ?? new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                //NotBefore = expires,
                Expires = DateTime.Now.AddMinutes(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
        }


         string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var randomNumberGenerator = RandomNumberGenerator.Create())
            {
                randomNumberGenerator.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

    }



}
/*
 * File: JwtTokenGenerator.cs
 * Project: sreehariaranghat
 * File Created: Wednesday, 22nd November 2023 10:18:48 am
 * Author: Sreehari Aranghat (info@aranghattech.com)
 * -----
 * Last Modified: Wednesday, 22nd November 2023 10:18:50 am
 * Modified By: Sreehari Aranghat (info@aranghattech.com>)
 * -----
 * Copyright © 2023 , Aranghat Technologies Private Limited
 */


using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Ba.Platform.Utilities;

public static class JwtTokenGenerator {

    /// <summary>
    /// GenerateToken Returns a JWT Token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static string GenerateToken(List<Claim> claims)
    {

        var secret = "Batman is not really a bat and may be not even a pat";
        var key = Encoding.ASCII.GetBytes(GenerateKeyName(secret));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// GenerateKeyName Generates a key name from a phrase
    /// </summary>
    public static string GenerateKeyName(string phrase)
    {
        // Step 1: Create an acronym to distill entropy from the phrase
        string[] words = phrase.Split(' ');
        StringBuilder sb = new StringBuilder();
        foreach (string word in words)
        {
            if (!string.IsNullOrEmpty(word))
            {
                sb.Append(word[0]); // Take the first letter of each word
            }
        }

        // Step 2: Convert the acronym into a byte array
        byte[] nameBytes = Encoding.UTF8.GetBytes(sb.ToString());

        // Step 3: Hash the bytes to ensure a 512-bit length
        using (SHA512 shaM = SHA512.Create())
        {
            byte[] hashBytes = shaM.ComputeHash(nameBytes);

            // Step 4: (Optional) Convert the hash to a Base64 string for use as a key name
            string keyName = Convert.ToBase64String(hashBytes);
            return keyName;
        }
    }

}
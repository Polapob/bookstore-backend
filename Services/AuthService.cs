

using bookstore_backend.Repositories;
using bookstore_backend.Models;
using bookstore_backend.Dtos;
using System.Text.RegularExpressions;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace bookstore_backend.Services;

public interface IAuthService
{
    public Task<User> Register(RegisterDTO registerDTO);
    public Task<SignInResult> SignIn(SignInDTO signInDTO);
    public bool SignOut(SignOutDTO signOutDTO);
    public Task<string?> RefreshAccessToken(RefreshAccessTokenDTO refreshAccessTokenDTO);
}

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;

    public AuthService(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<User> Register(RegisterDTO registerDTO)
    {
        if (registerDTO.Password != registerDTO.ConfirmPassword)
        {
            throw new BadHttpRequestException("Your password isn't as same as confirm password");
        }
        var strongPassword = new Regex("(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})");
        if (!strongPassword.IsMatch(registerDTO.Password))
        {
            throw new BadHttpRequestException("Your password isn't strong enough.");
        }
        var email = new Regex("^\\S+@\\S+\\.\\S+$");
        if (!email.IsMatch(registerDTO.Email))
        {
            throw new BadHttpRequestException("Your email format isn't correct");
        }
        User? user = await _userRepository.GetUserByEmail(registerDTO.Email);

        if (user != null)
        {
            throw new BadHttpRequestException("You already register by using this email");
        }
        string password = BCrypt.Net.BCrypt.HashPassword(registerDTO.Password);

        User newUser = new User()
        {
            UserId = Guid.NewGuid().ToString(),
            FirstName = registerDTO.FirstName,
            LastName = registerDTO.LastName,
            Username = registerDTO.Username,
            Email = registerDTO.Email,
            Password = password,
            Role = Roles.NORMAL,
            CreateAt = new DateTime(),
        };
        return await _userRepository.CreateUser(newUser);

    }
    public async Task<SignInResult> SignIn(SignInDTO signInDTO)
    {
        var email = new Regex("^\\S+@\\S+\\.\\S+$");
        if (!email.IsMatch(signInDTO.Email))
        {
            throw new BadHttpRequestException("Your email format isn't correct");
        }
        User? user = await _userRepository.GetUserByEmail(signInDTO.Email);
        if (user == null)
        {
            throw new UnauthorizedAccessException("Your email is unauthorized");
        }
        if (!BCrypt.Net.BCrypt.Verify(signInDTO.Password, user.Password))
        {
            throw new UnauthorizedAccessException("Your password is incorrect");
        }
        string accessToken = createToken(user, 86400000);
        string refreshToken = createToken(user, 2592000000);

        return new SignInResult
        {
            user = user,
            accessToken = accessToken,
            refreshToken = refreshToken
        };
    }
    public bool SignOut(SignOutDTO signOutDTO)
    {
        VerifyTokenResult? accessJWT = verifyToken(signOutDTO.accessToken);
        if (accessJWT != null)
        {
            return true;
        }
        VerifyTokenResult? refreshJWT = verifyToken(signOutDTO.refreshToken);
        if (refreshJWT == null)
        {
            return false;
        }
        return true;
    }
    public async Task<string?> RefreshAccessToken(RefreshAccessTokenDTO refreshAccessTokenDTO)
    {
        VerifyTokenResult? refreshJWT = verifyToken(refreshAccessTokenDTO.refreshToken);

        if (refreshJWT == null)
        {
            throw new UnauthorizedAccessException("User doesn't authorize to the website");
        }

        User? user = await _userRepository.GetUserById(refreshJWT.UserId);

        if (user == null)
        {
            throw new UnauthorizedAccessException("User doesn't authorize to the website");
        }
        return createToken(user, 86400000);
    }

    private string createToken(User user, long expireInMs)
    {
        List<Claim> claims = new List<Claim>
        {
            new Claim("id",user.UserId),
            new Claim(ClaimTypes.Name,user.FirstName + "" + user.LastName),
            new Claim(ClaimTypes.Email,user.Email),
            new Claim(ClaimTypes.GivenName,user.Username),
        };
        string? jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET");
        if (jwtSecret == null)
        {
            throw new Exception("JWT_SECRET is required in .env");
        }
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        SecurityKey key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtSecret));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        JwtSecurityToken securityToken = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddMilliseconds(expireInMs),
            signingCredentials: credentials
        );

        string token = tokenHandler.WriteToken(securityToken);
        return token;
    }

    private VerifyTokenResult? verifyToken(string token)
    {
        string? jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET");
        if (jwtSecret == null)
        {
            throw new Exception("JWT_SECRET is required in .env");
        }
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        SecurityKey key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtSecret));

        try
        {
            TokenValidationParameters validationParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };
            tokenHandler.ValidateToken(token, validationParams, out SecurityToken validatedToken);
            JwtSecurityToken decodedJwt = (JwtSecurityToken)validatedToken;
            string userId = decodedJwt.Claims.First(x => x.Type == "id").Value;
            string email = decodedJwt.Claims.First(x => x.Type == ClaimTypes.Email).Value;

            return new VerifyTokenResult
            {
                UserId = userId,
                Email = email,
            };
        }
        catch
        {
            return null;
        }
    }
}
using bookstore_backend.Models;

namespace bookstore_backend.Dtos;


public class RegisterDTO
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string ConfirmPassword { get; set; } = null!;
    public string Username { get; set; } = null!;
}
public class SignInDTO
{
    public string Email = null!;
    public string Password = null!;
}

public class SignOutDTO
{
    public string accessToken = null!;
    public string refreshToken = null!;
}

public class RefreshAccessTokenDTO
{
    public string refreshToken = null!;
}

public class SignInResult
{
    public User user = null!;

    public string accessToken = null!;
    public string refreshToken = null!;

}

public class VerifyTokenResult
{
    public string UserId = null!;
    public string Email = null;
}
namespace bookstore_backend.Models;


public enum Roles
{
    NORMAL,
    ADMIN
}
public class User
{
    public string UserId { get; set; } = null!;
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string Username { get; set; } = null!;
    public Roles Role { get; set; }
    public string? ShippingAddress { get; set; }
    public DateTime CreateAt { get; set; }
    public DateTime UpdateAt { get; set; }
    public DateTime DeleteAt { get; set; }



};
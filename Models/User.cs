namespace bookstore_backend.Models;


public enum Roles
{
    NORMAL,
    ADMIN
}
public class User
{
    public string? UserId { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string? Username { get; set; }
    public Roles Role { get; set; }
    public string? ShippingAddress { get; set; }
    public DateTime CreateAt { get; set; }
    public DateTime UpdateAt { get; set; }
    public DateTime DeleteAt { get; set; }



};
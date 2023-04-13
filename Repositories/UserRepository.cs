using bookstore_backend.Contexts;
using bookstore_backend.Models;
using Microsoft.EntityFrameworkCore;

namespace bookstore_backend.Repositories;
public interface IUserRepository
{
    Task<User> CreateUser(User user);
    Task<User?> GetUserById(string id);
    Task<User?> GetUserByEmail(string email);
}

public class UserRepository : IUserRepository
{
    private readonly UserContext _userContext;
    public UserRepository(UserContext userContext)
    {
        _userContext = userContext;
    }

    public async Task<User> CreateUser(User user)
    {
        try
        {
            await _userContext.Users.AddAsync(user);
            await _userContext.SaveChangesAsync();
            return user;
        }
        catch
        {
            throw new SystemException("Internal server error");
        }

    }
    public async Task<User?> GetUserById(string id)
    {

        User? user = await _userContext.Users.AsNoTracking().Where(user => user.UserId == id).FirstOrDefaultAsync().ConfigureAwait(true);
        return user;
    }

    public async Task<User?> GetUserByEmail(string email)
    {
        User? user = await _userContext.Users.AsNoTracking().Where(user => user.Email == email).FirstOrDefaultAsync().ConfigureAwait(true);
        return user;
    }

}
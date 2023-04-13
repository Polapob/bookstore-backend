using Microsoft.EntityFrameworkCore;
using System;
using bookstore_backend.Models;

namespace bookstore_backend.Contexts;

public class UserContext : DbContext
{
    protected readonly IConfiguration _config;
    public UserContext(IConfiguration config)
    {
        _config = config;
    }

    public DbSet<User> Users { get; set; } = null!;

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        // connect to postgres with connection string from app settings
        var postgresConnectionString = Environment.GetEnvironmentVariable("POSTGRES_CONNECTION_STRING");
        options.UseNpgsql(postgresConnectionString);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>();
    }

}
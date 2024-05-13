using Microsoft.EntityFrameworkCore;

namespace WebApplicationTemplate.Model.Entity;

/// <summary>
/// EFCore数据库构造
/// </summary>
public class MyDBContext : DbContext
{
    /// <summary>
    /// 用户表
    /// </summary>
    public DbSet<User> Users { get; set; }

    /// <summary>
    /// option
    /// </summary>
    /// <param name="option"></param>
    public MyDBContext(DbContextOptions<MyDBContext> option) : base(option)
    {

    }
}


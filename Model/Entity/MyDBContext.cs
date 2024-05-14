using System.Reflection;
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

    /// <summary>
    /// 实体配置类
    /// </summary>
    /// <param name="modelBuilder"></param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<User>().HasKey(e => e.ID);
        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(e => e.UserName).HasMaxLength(20).IsRequired();
            entity.Property(e => e.Email).IsRequired(false);
        });
    }
}


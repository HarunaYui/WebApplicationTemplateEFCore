using System.Security.Claims;
using Dapper;
using Dapper.Contrib.Extensions;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using MySqlConnector;
using WebApplicationTemplate.ActionFilter;
using WebApplicationTemplate.AppDB;
using WebApplicationTemplate.JWT;
using WebApplicationTemplate.Model;
using WebApplicationTemplate.Model.Entity;
using WebApplicationTemplate.Model.Enums;
using WebApplicationTemplate.Model.From;

namespace WebApplicationTemplate.Controllers;

/// <summary>
/// 用户控制器
/// </summary>
[Route("api/[controller]/[action]")]
[ApiController]
[Authorize]
public class UserController : Controller
{
    private readonly IMemoryCache _memoryCache;
    private readonly IConfiguration _config;
    private readonly ILogger<UserController> _logger;
    private readonly IOptionsSnapshot<JwtSettings> _jwtsettingOpt;
    private readonly MyDBContext _dbContext;
    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="jwtsettingOpt"></param>
    /// <param name="logger"></param>
    /// <param name="config"></param>
    /// <param name="memoryCache"></param>
    /// <param name="myDbContext"></param>
    /// <param name="cnn"></param>
    public UserController(IOptionsSnapshot<JwtSettings> jwtsettingOpt, ILogger<UserController> logger, IConfiguration config, IMemoryCache memoryCache, MyDBContext myDbContext)
    {
        _jwtsettingOpt = jwtsettingOpt;
        _logger = logger;
        _config = config;
        _memoryCache = memoryCache;
        _dbContext = myDbContext;
    }

    /// <summary>
    /// 用户登录
    /// </summary>
    /// <param name="userRegister"></param>
    /// <param name="userRegisterOpt"></param>
    /// <returns></returns>
    [HttpPost]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(bool))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(string))]
    public async Task<IActionResult> UserLogin([FromBody]UserRegister userRegister, [FromServices] IValidator<UserRegister> userRegisterOpt)
    {
        var validateresult = await userRegisterOpt.ValidateAsync(userRegister);
        if (!validateresult.IsValid)
            return BadRequest(validateresult.ToString());
        var userSearchResult = await _dbContext.Users.FirstOrDefaultAsync(s => s.UserName == userRegister.UserName);
        if (userSearchResult == null)
            return NotFound("未查询到用户");
        if (userSearchResult.Password != userRegister.PassWord)
            return BadRequest("密码错误");
        var jwt = _memoryCache.GetOrCreate($"ID:{userSearchResult.ID}", (e) =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7);
            if (userSearchResult.Role == UserRole.用户)
            {
                List<Claim> claims =
                [
                    new(ClaimTypes.NameIdentifier, userSearchResult.ID.ToString()),
                    new(ClaimTypes.Name, userSearchResult.UserName),
                    new(ClaimTypes.Role, "user")
                ];
                string? key = _jwtsettingOpt.Value.SecrectKey;
                DateTime expire = DateTime.Now.AddSeconds(_jwtsettingOpt.Value.ExpireSeconds);
                string jwt = JwtHelper.JwtCreate(claims, key, expire);
                _logger.LogDebug($"{userSearchResult.UserName}登陆成功");
                return jwt;
            }
            else
            {
                List<Claim> claims =
                [
                    new(ClaimTypes.NameIdentifier, userSearchResult.ID.ToString()),
                    new(ClaimTypes.Name, userSearchResult.UserName),
                    new(ClaimTypes.Role, "user"),
                    new(ClaimTypes.Role, "admin")
                ];
                string? key = _jwtsettingOpt.Value.SecrectKey;
                DateTime expire = DateTime.Now.AddSeconds(_jwtsettingOpt.Value.ExpireSeconds);
                string jwt = JwtHelper.JwtCreate(claims, key, expire);
                _logger.LogDebug($"{userSearchResult.UserName}登陆成功");
                return jwt;
            }
        });
        return Ok(jwt);
    }

    /// <summary>
    /// 用户注册
    /// </summary>
    /// <param name="userRegister"></param>
    /// <param name="userRegisterOpt"></param>
    /// <returns></returns>
    [HttpPost]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK,Type = typeof(bool))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(string))]
    public async Task<IActionResult> RegisterUser([FromBody] UserRegister userRegister, [FromServices] IValidator<UserRegister> userRegisterOpt)
    {
        var validateresult = await userRegisterOpt.ValidateAsync(userRegister);
        if (!validateresult.IsValid)
            return BadRequest(validateresult.ToString());
        var userExist = await _dbContext.Users.Select(s => s.UserName == userRegister.UserName).FirstOrDefaultAsync();
        if (userExist)
            return BadRequest("用户已存在");
        string salt = UserPasswordSet.CreateSalt(userRegister.UserName);
        string password = UserPasswordSet.SaltedPassword(userRegister.PassWord, salt);
        User newuser = new(){UserName = userRegister.UserName,Password = userRegister.PassWord};
        var result = await _dbContext.Users.AddAsync(newuser);
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    /// <summary>
    /// 获取所有用户信息
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(Roles = "admin")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(List<User>))]
    public async Task<IActionResult> GetAllUser()
    {
        var users = _dbContext.Users.ToList();
        return Ok(users);
    }

    /// <summary>
    /// 添加管理员
    /// </summary>
    /// <returns></returns>
    [HttpPost]
    [Authorize(Roles = "admin")]
    [NotRateTransaction]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(string))]
    public IActionResult AddAdmin()
    {
        var userclaims = User.Claims.ToList();
        string? key = _jwtsettingOpt.Value.SecrectKey;
        DateTime expire = DateTime.Now.AddSeconds(_jwtsettingOpt.Value.ExpireSeconds);
        var result = JwtHelper.JwtAddAdmin(userclaims, key, expire);
        _logger.LogDebug($"{userclaims[1].Value}授权管理员成功");
        return Ok(result);
    }

    /// <summary>
    /// 显示jwt
    /// </summary>
    /// <returns></returns>
    [HttpPost]
    [Authorize(Roles = "admin")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(List<>))]
    public IActionResult ShowJwtMessage()
    {
        string id = User.FindFirst(ClaimTypes.NameIdentifier)!.Value;
        string userName = User.FindFirst(ClaimTypes.NameIdentifier)!.Value;
        IEnumerable<Claim> roleClaims = User.FindAll(ClaimTypes.Role);
        string roleNames = string.Join(',', roleClaims.Select(x => x.Value));
        _logger.LogDebug($"{userName}查询了jwt信息");
        return Ok(new { ID = id, UserName = userName, roleNames = roleNames });
    }
}

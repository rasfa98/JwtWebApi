using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Dapper;
using JwtWebApi.Dtos;
using JwtWebApi.models;
using JwtWebApi.Models;
using JwtWebApi.Services.UserService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MySqlConnector;

namespace JwtWebApi.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var username = _userService.GetUsername();

            return Ok(username);
        }

        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            var user = new
            {
                Username = request.Username,
                PasswordHash = passwordHash,
                VerificationToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            };

            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var existingUser = await connection.QueryFirstOrDefaultAsync("SELECT * FROM users WHERE username = @Username", user);

            if (existingUser != null)
            {
                return Conflict("User already exists.");
            }

            await connection.ExecuteAsync("INSERT INTO users (username, passwordHash, verificationToken) VALUES (@Username, @PasswordHash, @VerificationToken)", user);

            return Ok("User created.");
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(LoginDto request)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE username = @Username", request);

            if (user == null)
            {
                return BadRequest("User not found.");
            }

            if (user.VerifiedAt == default(DateTime))
            {
                return Unauthorized("User not verified.");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken, user.Id);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE refreshToken = @RefreshToken", new { RefreshToken = refreshToken });

            if (user == null || (user.RefreshToken != refreshToken))
            {
                return BadRequest("Invalid refresh token.");
            }

            if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken, user.Id);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        [HttpPost("verify")]
        public async Task<ActionResult<string>> Verify(string token)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE verificationToken = @Token", new { Token = token });

            if (user == null)
            {
                return BadRequest("Invalid token.");
            }

            await connection.ExecuteAsync("UPDATE users SET verifiedAt = @VerifiedAt WHERE id = @Id", new { VerifiedAt = DateTime.Now, Id = user.Id });

            return Ok("User verified.");
        }

        private async void SetRefreshToken(RefreshToken newRefreshToken, int userId)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            await connection.ExecuteAsync("UPDATE users SET refreshToken = @Token, tokenCreated = @Created, tokenExpires = @Expires WHERE id = @Id", new { Token = newRefreshToken.Token, Created = newRefreshToken.Created, Expires = newRefreshToken.Expires, Id = userId });
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
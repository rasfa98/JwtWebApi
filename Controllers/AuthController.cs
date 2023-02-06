using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Dapper;
using JwtWebApi.Dtos;
using JwtWebApi.models;
using JwtWebApi.Models;
using JwtWebApi.Services.EmailService;
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
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService, IEmailService emailService)
        {
            _configuration = configuration;
            _userService = userService;
            _emailService = emailService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> Auth()
        {
            var email = _userService.GetEmail();

            return Ok(email);
        }

        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto request)
        {
            string passwordHash = CreatePasswordHash(request.Password);
            string token = CreateToken();

            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                VerificationToken = token,
            };

            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var existingUser = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE email = @Email", user);

            if (existingUser != null)
            {
                return Conflict("Email already exists.");
            }

            await connection.ExecuteAsync("INSERT INTO users (email, passwordHash, verificationToken) VALUES (@Email, @PasswordHash, @VerificationToken)", user);

            _emailService.SendEmail(new EmailDto { To = user.Email, Subject = "Verify account", Body = $"Verify account using token {user.VerificationToken}" });

            return Ok("User created.");
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(LoginDto request)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE email = @Email", request);

            if (user == null)
            {
                return BadRequest("User not found.");
            }

            if (user.VerifiedAt == default(DateTime))
            {
                return Unauthorized("User not verified.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateJwtToken(user);
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

            string token = CreateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            SetRefreshToken(newRefreshToken, user.Id);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = CreateToken(),
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

        [HttpPost("forgot-password")]
        public async Task<ActionResult<string>> ForgotPassword(string email)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE email = @Email", new { Email = email });

            if (user == null)
            {
                return BadRequest("User not found.");
            }

            string token = CreateToken();

            await connection.ExecuteAsync("UPDATE users SET passwordResetToken = @PasswordResetToken, resetTokenExpires = @ResetTokenExpires WHERE id = @Id", new { ResetTokenExpires = DateTime.Now.AddDays(1), PasswordResetToken = token, Id = user.Id });

            _emailService.SendEmail(new EmailDto { To = user.Email, Subject = "Reset password", Body = $"Reset password using token {token}" });

            return Ok("You may now reset your password.");
        }

        [HttpPost("reset-password")]
        public async Task<ActionResult<string>> ResetPassword(ResetPasswordDto request)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE passwordResetToken = @PasswordResetToken", new { PasswordResetToken = request.Token });

            if (user == null || user.ResetTokenExpires < DateTime.Now)
            {
                return BadRequest("Invalid token.");
            }

            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            await connection.ExecuteAsync("UPDATE users SET passwordResetToken = @PasswordResetToken, resetTokenExpires = @ResetTokenExpires, passwordHash = @PasswordHash WHERE id = @Id", new { ResetTokenExpires = (string?)null, PasswordResetToken = (string?)null, PasswordHash = passwordHash, Id = user.Id });

            return Ok("Password has been reset.");
        }

        private string CreateToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
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

        private string CreatePasswordHash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private bool VerifyPasswordHash(string password, string passwordHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        private string CreateJwtToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email),
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
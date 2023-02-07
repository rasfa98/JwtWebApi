using Dapper;
using JwtWebApi.Dtos;
using JwtWebApi.Models;
using JwtWebApi.Services.EmailService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace JwtWebApi.Controllers
{
    [Route("api/users")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public UserController(IConfiguration configuration, IEmailService emailService)
        {
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDto>>> GetUsers()
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var users = await connection.QueryAsync("SELECT id, email, isAdmin, verifiedAt FROM users");

            return Ok(users);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<UserDto>> GetUser(int id)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync("SELECT id, email, isAdmin, verifiedAt FROM users WHERE id = @Id", new { Id = id });

            if (user == null)
            {
                return NotFound("User not found.");
            }

            return Ok(user);
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteUser(int id)
        {
            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var user = await connection.QueryFirstOrDefaultAsync("SELECT * FROM users WHERE id = @Id", new { Id = id });

            if (user == null)
            {
                return NotFound("User not found.");
            }

            await connection.ExecuteAsync("DELETE FROM users WHERE id = @Id", new { Id = id });

            return NoContent();
        }

        [HttpPut("{id}")]
        public async Task<ActionResult> UpdateUser(int id, UpdateUserDto request)
        {
            var user = new User
            {
                Id = id,
                Email = request.Email,
                IsAdmin = request.IsAdmin
            };

            using var connection = new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));

            var existingUser = await connection.QueryFirstOrDefaultAsync<User>("SELECT * FROM users WHERE email = @Email AND id != @Id", user);

            if (existingUser != null)
            {
                return Conflict("Email already exists.");
            }

            await connection.ExecuteAsync("UPDATE users SET email = @Email, isAdmin = @IsAdmin WHERE id = @Id", user);

            return NoContent();
        }
    }
}
using Dapper;
using JwtWebApi.Dtos;
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
        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;

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
    }
}
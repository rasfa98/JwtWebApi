using System.ComponentModel.DataAnnotations;

namespace JwtWebApi.Dtos
{
    public class UpdateUserDto
    {
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        public bool IsAdmin { get; set; }
    }
}
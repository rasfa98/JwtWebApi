using System.ComponentModel.DataAnnotations;

namespace JwtWebApi.Dtos
{
    public class UpdateUserDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public bool IsAdmin { get; set; }
    }
}
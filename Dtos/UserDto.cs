namespace JwtWebApi.Dtos
{
    public class UserDto
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public bool IsAdmin { get; set; }
        public DateTime VerifiedAt { get; set; }
    }
}
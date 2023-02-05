using JwtWebApi.Dtos;

namespace JwtWebApi.Services.EmailService
{
    public interface IEmailService
    {
        void SendEmail(EmailDto request);
    }
}
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MailKit.Net.Smtp;
using MimeKit;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using TESTIDENTITYEMAIL.Dto;
using TESTIDENTITYEMAIL.Models;

namespace TESTIDENTITYEMAIL.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Registeration([FromBody] RegisterDto model)
        {
            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
                return BadRequest("Email and password are required.");

            var user = await GetUser(model.Email);
            if (user != null)
                return BadRequest("User already exists.");

            var newUser = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(newUser, model.Password);

            if (!result.Succeeded)
                return BadRequest("Registration failed.");

            var emailCode = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var sendEmailResult = SendEmail(newUser.Email, emailCode);
            return Ok(sendEmailResult);
        }


        // إرسال إيميل تأكيد
        private string SendEmail(string email, string emailCode)
        {
            var emailMessage = new StringBuilder();
            emailMessage.AppendLine("<html><body>");
            emailMessage.AppendLine($"<p>عزيزي {email}،</p>");
            emailMessage.AppendLine("<p>شكرًا لتسجيلك. يرجى استخدام رمز التحقق التالي:</p>");
            emailMessage.AppendLine($"<h2>{emailCode}</h2>");
            emailMessage.AppendLine("<p>يرجى إدخال هذا الرمز لإكمال التسجيل.</p>");
            emailMessage.AppendLine("</body></html>");

            var mimeMessage = new MimeMessage();
            mimeMessage.To.Add(MailboxAddress.Parse(email));
            mimeMessage.From.Add(MailboxAddress.Parse("gabe.bartell@ethereal.email"));
            mimeMessage.Subject = "تأكيد البريد الإلكتروني";
            mimeMessage.Body = new TextPart("html") { Text = emailMessage.ToString() };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("gabe.bartell@ethereal.email", "sZwEPRyeZ7c387vsab");
            smtp.Send(mimeMessage);
            smtp.Disconnect(true);

            return "تم إرسال رسالة تأكيد إلى بريدك الإلكتروني.";
        }

        // تأكيد البريد الإلكتروني - باستخدام Body
        [HttpPost("Confirmation")]
        public async Task<IActionResult> Confirmation([FromBody] ConfirmationRequest request)
        {
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Code))
                return BadRequest("يرجى إدخال البريد الإلكتروني ورمز التأكيد.");

            var user = await GetUser(request.Email);
            if (user == null)
                return BadRequest("المستخدم غير موجود.");

            var result = await _userManager.ConfirmEmailAsync(user, request.Code);
            if (!result.Succeeded)
                return BadRequest("رمز التأكيد غير صحيح.");

            return Ok("تم تأكيد البريد الإلكتروني بنجاح.");
        }

        // تسجيل الدخول - باستخدام Body
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                return BadRequest("يرجى إدخال البريد الإلكتروني وكلمة المرور.");

            var user = await GetUser(request.Email);
            if (user == null)
                return Unauthorized("المستخدم غير موجود.");

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (!isEmailConfirmed)
                return BadRequest("يجب تأكيد البريد الإلكتروني قبل تسجيل الدخول.");

            // تحقق من كلمة المرور
            if (!await _userManager.CheckPasswordAsync(user, request.Password))
                return Unauthorized("كلمة المرور غير صحيحة.");

            var token = GenerateToken(user);
            return Ok(new { message = "تم تسجيل الدخول بنجاح", token });
        }

        // توليد توكن JWT
        private string GenerateToken(IdentityUser user)
        {
            var key = Encoding.ASCII.GetBytes("Qw12ER34TY56Ui78oi98v2bNh78JK4Hods7uUj12");
            var securityKey = new SymmetricSecurityKey(key);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage() => "هذه رسالة من endpoint محمي.";

        // جلب المستخدم من خلال البريد الإلكتروني
        private async Task<IdentityUser> GetUser(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }
    }

}

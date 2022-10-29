using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<object> GetMe()
        {
            var username = _userService.GetMyName();
            return Ok(username);
            /*var username = User?.Identity?.Name;
            var username2 = User.FindFirstValue(ClaimTypes.Name);
            var role = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new {username, username2, role});*/
        }

        

        [HttpPost]
        public async Task<ActionResult<User>> Register(UserDTO userDTO)
        {
            CreatePasswordHash(userDTO.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Username = userDTO.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost]
        public async Task<ActionResult<string>> Login(UserDTO userDTO)
        {
            if(user.Username != userDTO.Username)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(userDTO.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong passowrd");
            }
            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                

            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}

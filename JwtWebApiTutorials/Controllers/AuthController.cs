using JwtWebApiTutorials.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtWebApiTutorials.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		public static User user = new User();
		private readonly IConfiguration configuration;

		public AuthController(IConfiguration configuration)
        {
			this.configuration = configuration;
		}

        [HttpPost("registers")]
		public async Task<ActionResult<User>>Register(UserDto request)
		{
			CreatePassword(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
			user.Username = request.UserName;
			user.PasswordHash = passwordHash;
			user.PasswordSalt = passwordSalt;
			return Ok(user);
		}
		[HttpPost("login")]
		public async Task<ActionResult<string>> Login(UserDto request)
		{
			if(user.Username!=request.UserName)
			{
				return BadRequest("User Not found");
			}
			if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
			{
				return BadRequest("Wrong Password");
			}

			string _token = CreateJwtToken(user);

			return Ok(_token);
		}

		private string CreateJwtToken(User user)
		{
			List<Claim> claims = new List<Claim>
			{
				new Claim(ClaimTypes.Name,user.Username)
			};

			var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("AppSettings:TokenSecret").Value));

			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

			//---------------- JWT Payload
			var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);

			var jwt= new JwtSecurityTokenHandler().WriteToken(token);


			return jwt;
		}
		private void CreatePassword(string password,out byte[] passwordHash,out byte[]passwordSalt)
		{
			using (var hmac = new HMACSHA512())
			{
				passwordSalt = hmac.Key;
				passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
			}
		}
		private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[]passwordSalt)
		{
			using (var hmac = new HMACSHA512(passwordSalt))
			{
				byte[] computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
				return computedHash.SequenceEqual(passwordHash);
			}
		}
	}
}

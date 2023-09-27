using Authentication.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "monsite.com",
            ValidAudience = "monsite.com",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MaCleSecreteTresLongue"))
        };
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy =>
                      {
                          policy.WithOrigins("http://127.0.0.1:5500")
                          .AllowAnyHeader()
                          .AllowAnyMethod();
                      });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(MyAllowSpecificOrigins);
app.UseHttpsRedirection();

app.UseAuthentication();
//app.UseAuthorization();

app.MapPost("/register", async (IConfiguration configuration, HttpContext context) =>
{
    var request = await JsonSerializer.DeserializeAsync<UtilisateurEntity>(context.Request.Body);
    if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.MotDePasse) || string.IsNullOrWhiteSpace(request.NomUtilisateur))
    {
        context.Response.StatusCode = 400;
        return;
    }

    UtilisateurRepo ur = new(configuration);
    
    // Simulez l'enregistrement en base de données
    // Utilisez une vraie base de données dans une application de production
    var salt = GenerateSalt();
    var hashedPassword = HashPassword(request.MotDePasse, salt);
    var newUser = new UtilisateurEntity
    {
        Id = 0,
        NomUtilisateur = request.NomUtilisateur,
        Email = request.Email,
        MotDePasse = hashedPassword,
        Salt= Convert.ToBase64String(salt),
    };
    ur.Create(newUser);
    
    var userId = await ur.GetIDAsync(request.Email);  // Simuler un ID utilisateur

    // Générer un JWT
    var token = GenerateToken(request.Email, userId.ToString());

    var response = new { token };
    await context.Response.WriteAsJsonAsync(response);
});

string GenerateToken(string email, string userId)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Email, email),
        new Claim(ClaimTypes.NameIdentifier, userId),
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MaCleSecreteTresLongue"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: "monsite.com",
        audience: "monsite.com",
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

string HashPassword(string password, byte[] salt)
{
    using var sha256 = SHA256.Create();

    // Convertir le mot de passe en tableau d'octets
    var passwordBytes = Encoding.UTF8.GetBytes(password);

    // Concaténer le mot de passe et le sel
    var saltedPassword = new byte[passwordBytes.Length + salt.Length];
    Array.Copy(passwordBytes, 0, saltedPassword, 0, passwordBytes.Length);
    Array.Copy(salt, 0, saltedPassword, passwordBytes.Length, salt.Length);

    // Hacher le mot de passe salé
    var hash = sha256.ComputeHash(saltedPassword);

    return Convert.ToBase64String(hash);
}


byte[] GenerateSalt(int size = 32)
{
    byte[] salt = new byte[size];
    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }
    return salt;
}

app.MapPost("/login", async (IConfiguration configuration, HttpContext context) =>
{
    var request = await JsonSerializer.DeserializeAsync<UtilisateurEntity>(context.Request.Body);
    if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.MotDePasse))
    {
        context.Response.StatusCode = 400;
        return;
    }

    UtilisateurRepo ur = new(configuration);

    // Simulez l'enregistrement en base de données
    // Utilisez une vraie base de données dans une application de production
    var saltTask = ur.GetSaltAsync(request.Email);
    string? result = await saltTask;
    byte[] salt = null;

    if (result != null)
    {
       salt = Convert.FromBase64String(result);
    }
    else
    {
        Console.WriteLine("La chaîne est null.");
    }

    var pwdTask = ur.GetPasswordAsync(request.Email);
    string? pwd = await pwdTask;

    var hashedPassword = HashPassword(request.MotDePasse, salt);

    if (hashedPassword == pwd)
    {
    var userId = await ur.GetIDAsync(request.Email);  // Simuler un ID utilisateur

    // Générer un JWT
    var token = GenerateToken(request.Email, userId.ToString());

    var response = new { token };
    await context.Response.WriteAsJsonAsync(response);

    }

});

app.Run();


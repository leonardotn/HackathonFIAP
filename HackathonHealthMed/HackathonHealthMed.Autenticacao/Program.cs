using HackathonHealthMed.Autenticacao.Data;
using HackathonHealthMed.Autenticacao.Services.Implementations;
using HackathonHealthMed.Autenticacao.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Prometheus;
using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AutenticacaoDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AutenticacaoConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AutenticacaoDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAutenticacaoService, AutenticacaoService>();


var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Autenticação - Health Med",
        Version = "v1",
        Description = "Autenticação da ferramenta Health Med",
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme. " +
       "Enter 'Bearer'[space] and then your token in the text input below.",
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                          new OpenApiSecurityScheme
                          {
                              Reference = new OpenApiReference
                              {
                                  Type = ReferenceType.SecurityScheme,
                                  Id = "Bearer"
                              }
                          },
                         new string[] {}
                    }
                });
});

builder.Services.AddAuthorization();
builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
    options.JsonSerializerOptions.WriteIndented = true;
}); ;

var app = builder.Build();

// Métricas - Prometheus

var memoryUsageGauge = Metrics.CreateGauge("dotnet_memory_usage_bytes", "Uso da memória em bytes.");
var cpuUsageGauge = Metrics.CreateGauge("dotnet_cpu_usage_percent", "Uso do CPU em porcentagem.");


var timer = new System.Timers.Timer(5000);
timer.Elapsed += (sender, e) =>
{
    var process = Process.GetCurrentProcess();
    memoryUsageGauge.Set(process.WorkingSet64);
    cpuUsageGauge.Set(GetCpuUsage(process));
};
timer.Start();

static double GetCpuUsage(Process process)
{
    var cpuCounter = new PerformanceCounter("Process", "% Processor Time", process.ProcessName);
    return cpuCounter.NextValue();
}

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<AutenticacaoDbContext>();

    // Aplica as migrações
    context.Database.Migrate();
}


app.UseSwagger();
app.UseSwaggerUI(c =>
{
	c.SwaggerEndpoint("/swagger/v1/swagger.json", "Autenticação Health Med");
});


app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Prometheus 
app.UseMetricServer();
app.UseHttpMetrics();

app.MapControllers();

app.Run();

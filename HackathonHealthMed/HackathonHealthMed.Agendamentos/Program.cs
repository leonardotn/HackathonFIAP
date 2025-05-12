using HackathonHealthMed.Agendamentos.Data;
using HackathonHealthMed.Agendamentos.Services;
using HackathonHealthMed.Agendamentos.Services.Interfaces;
using MassTransit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using HackathonHealthMed.Agendamentos.Eventos;
using System.Diagnostics;
using Prometheus;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddDbContext<AgendamentoDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AgendamentosConnection")));

builder.Services.AddControllers();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Agendamento", Version = "v1" });

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

var configuration = builder.Configuration;
var filaAtualizaStatusConsulta = builder.Configuration["MassTransit:FilaAtualizaStatusConsulta"];


var servidor = configuration.GetSection("MassTransit")["Servidor"] ?? string.Empty;
var usuario = configuration.GetSection("MassTransit")["Usuario"] ?? string.Empty;
var senha = configuration.GetSection("MassTransit")["Senha"] ?? string.Empty;

builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<AtualizaStatusConsultaConsumer>();
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host(servidor, "/", h =>
        {
            h.Username(usuario);
            h.Password(senha);
        });

        cfg.ReceiveEndpoint(filaAtualizaStatusConsulta, e =>
        {
            e.Consumer<AtualizaStatusConsultaConsumer>(context);
        });
    });
});

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped<IAgendamentoService, AgendamentoService>();
builder.Services.AddScoped<IAutenticacaoApiService, AutenticacaoApiService>();
builder.Services.AddScoped<IHorarioApiService, HorarioApiService>();

builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "HackathonHealthMed",
            ValidAudience = "HackathonHealthMedAPI",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("K8XJ!pL2@3z$gW#qR6yVmTn9FsEcYdUb"))
        };
    });

builder.Services.AddAuthorization();

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
    var context = services.GetRequiredService<AgendamentoDbContext>();

    // Aplica as migrações
    context.Database.Migrate();
}

app.UseAuthentication();
app.UseAuthorization();

// Prometheus 
app.UseMetricServer();
app.UseHttpMetrics();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.MapControllers();

app.Run();

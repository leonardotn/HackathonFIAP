using HackathonHealthMed.GestaoHorarios.Data;
using HackathonHealthMed.GestaoHorarios.Eventos;
using HackathonHealthMed.GestaoHorarios.Services;
using HackathonHealthMed.GestaoHorarios.Services.Interfaces;
using MassTransit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Prometheus;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

var filaOcupaHorario = builder.Configuration["MassTransit:FilaOcupaHorario"];
var filaDesocupaHorario = builder.Configuration["MassTransit:FilaDesocupaHorario"];

var servidor = builder.Configuration["MassTransit:Servidor"];
var usuario = builder.Configuration["MassTransit:Usuario"];
var senha = builder.Configuration["MassTransit:Senha"];


builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<OcupaHorarioConsumer>();
    x.AddConsumer<DesocupaHorarioConsumer>();

    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host(servidor, "/", h =>
        {
            h.Username(usuario);
            h.Password(senha);
        });

        cfg.ReceiveEndpoint(filaOcupaHorario, e =>
        {
            e.Consumer<OcupaHorarioConsumer>(context);
        });

        cfg.ReceiveEndpoint(filaDesocupaHorario, e =>
        {
            e.Consumer<DesocupaHorarioConsumer>(context);
        });

    });
});


builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "gestaoHorario", Version = "v1" });

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

builder.Services.AddDbContext<GestaoHorarioDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("GestaoHorarioConnection"));
});

builder.Services.AddScoped<IHorarioConsultaService, HorarioConsultaService>();
builder.Services.AddScoped<IValorConsultaMedicoService, ValorConsultaMedicoService>();
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
    var context = services.GetRequiredService<GestaoHorarioDbContext>();

    // Aplica as migrações
    context.Database.Migrate();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Prometheus 
app.UseMetricServer();
app.UseHttpMetrics();


// Configure the HTTP request pipeline.


app.MapControllers();

app.Run();

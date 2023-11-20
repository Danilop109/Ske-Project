using System.Reflection;
using Api.Extension;
using AspNetCoreRateLimit;
using Microsoft.EntityFrameworkCore;
using Persistencia;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.ConfigureRatelimiting();
builder.Services.ConfigureApiVersioning();
builder.Services.AddSwaggerGen();
builder.Services.AddAutoMapper(Assembly.GetEntryAssembly());
builder.Services.ConfigureCors();
builder.Services.AddAplicacionServices();
builder.Services.AddJwt(builder.Configuration);

builder.Services.AddDbContext<ApiJwtContext>(options =>
{
    string connectionString = builder.Configuration.GetConnectionString("ConexMySql");
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});


var app = builder.Build();



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


using (var scope = app.Services.CreateScope())
{
	var services = scope.ServiceProvider;
	var loggerFactory = services.GetRequiredService<ILoggerFactory>();
	try
	{
		var context = services.GetRequiredService<ApiJwtContext>();
		await context.Database.MigrateAsync();
		await ApiContextSeed.SeedRolesAsync(context,loggerFactory);
		await ApiContextSeed.SeedAsync(context,loggerFactory);
	}
	catch (Exception ex)
	{
		var _logger = loggerFactory.CreateLogger<Program>();
		_logger.LogError(ex, "Ocurrio un error durante la migracion");
	}
}

app.UseCors("CorsPolicy");

app.UseHttpsRedirection();

app.UseIpRateLimiting();

app.UseAuthorization();

app.MapControllers();

app.Run();

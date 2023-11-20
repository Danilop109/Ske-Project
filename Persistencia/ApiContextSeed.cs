using System.Globalization;
using System.Reflection;
using CsvHelper;
using CsvHelper.Configuration;
using Dominio.Entities;
using Microsoft.Extensions.Logging;

namespace Persistencia;
public class ApiContextSeed
{
    public static async Task SeedAsync(ApiJwtContext context, ILoggerFactory loggerFactory)
    {
        try
        {
            //inicio de las insersiones en la db
            var ruta = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            if (!context.Users.Any())
            {
                using (var reader = new StreamReader("../Persistencia/Data/Csv/User.csv"))
                {
                    using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                    {
                        var list = csv.GetRecords<User>();
                        context.Users.AddRange(list);
                        await context.SaveChangesAsync();
                    }
                }
                
            }

            if (!context.UsersRols.Any())
            {
                using (var reader = new StreamReader("../Persistencia/Data/Csv/RoleUser.csv"))
                {
                    using (var csv = new CsvReader(reader, new CsvConfiguration(CultureInfo.InvariantCulture)
                    {
                        HeaderValidated = null, // Esto deshabilita la validación de encabezados
                        MissingFieldFound = null
                    }))
                    {
                        // Resto de tu código para leer y procesar el archivo CSV
                        var list = csv.GetRecords<UserRol>();
                        List<UserRol> entidad = new List<UserRol>();
                        foreach (var item in list)
                        {
                            entidad.Add(new UserRol
                            {
                                UsuarioId = item.UsuarioId,
                                RolId = item.RolId
                            });
                        }
                        context.UsersRols.AddRange(entidad);
                        await context.SaveChangesAsync();
                    }
                }
            }
        //fin de las insersiones en la db
        }
        catch (Exception ex)
        {
            var logger = loggerFactory.CreateLogger<ApiJwtContext>();
            logger.LogError(ex.Message);
        }
    }
    public static async Task SeedRolesAsync(ApiJwtContext context, ILoggerFactory loggerFactory)
    {
        try
        {
            if (!context.Rols.Any())
            {
                var roles = new List<Rol>()
                        {
                            new Rol{Id=1, Nombre="Administrador"},
                            new Rol{Id=2, Nombre="Empleado"},
                        };
                context.Rols.AddRange(roles);
                await context.SaveChangesAsync();
            }
        }
        catch (Exception ex)
        {
            var logger = loggerFactory.CreateLogger<ApiJwtContext>();
            logger.LogError(ex.Message);
        }
    }
}

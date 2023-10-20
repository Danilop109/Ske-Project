using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.EntityFrameworkCore;
using Persistencia;

namespace Aplicacion.Repository
{
    public class UserRepository : GenericRepository<User>, IUser
    {
        private readonly ApiJwtContext _context;
        public UserRepository(ApiJwtContext context) : base(context)
        {
            _context = context;
        }

        public async Task<User> GetByRefreshTokenAsync(string refreshToken)
        {
            return await _context.Users
                .Include(u => u.Rols)
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == refreshToken));
        }

        public async Task<User> GetByUsernameAsync(string username)
        {
            return await _context.Users
                .Include(u => u.Rols)
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());
        }

        public override async Task<IEnumerable<User>> GetAllAsync()
        {
            return await _context.Users
                .ToListAsync();
        }

        public override async Task<User> GetByIdAsync(int id)
        {
            return await _context.Users
            .FirstOrDefaultAsync(p => p.Id == id);
        }
        public override async Task<(int totalRegistros, IEnumerable<User> registros)> GetAllAsync(int pageIndez, int pageSize, string search)
        {
            var query = _context.Users as IQueryable<User>;

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(p => p.Username.ToLower().Contains(search));
            }

            query = query.OrderBy(p => p.Id);

            var totalRegistros = await query.CountAsync();
            var registros = await query
                .Skip((pageIndez - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (totalRegistros, registros);
        }

    //     public override async Task<IEnumerable<Mascota>> GetAllAsync()
    //     {
    //         return await _context.Mascotas
    //             .Include(p => p.Propietario)
    //             .Include(p => p.Especie)
    //             .Include(p => p.Raza)
    //             .ToListAsync();
    //     }


    //     public override async Task<Mascota> GetByIdAsync(int id)
    //     {
    //         return await _context.Mascotas
    //             .Include(p => p.Propietario)
    //             .Include(p => p.Especie)
    //             .Include(p => p.Raza)
    //         .FirstOrDefaultAsync(p => p.Id == id);
    //     }


    //     public override async Task<(int totalRegistros, IEnumerable<Mascota> registros)> GetAllAsync(int pageIndez, int pageSize, string search)
    // {
    //     var query = _context.Mascotas as IQueryable<Mascota>;


    //     if(!string.IsNullOrEmpty(search))
    //     {
    //         query = query.Where(p => p.Nombre.ToLower().Contains(search));
    //     }


    //     query = query.OrderBy(p => p.Id);
    //     var totalRegistros = await query.CountAsync();
    //     var registros = await query
    //         .Include(p => p.Propietario)
    //         .Skip((pageIndez - 1) * pageSize)
    //         .Take(pageSize)
    //         .ToListAsync();


    //     return (totalRegistros, registros);
    // }


    //     //CONSULTA A-3: Mostrar las mascotas que se encuentren registradas cuya especie sea felina.


    //     public async Task<IEnumerable<object>> GetPetEspecie()
    //     {
    //         return await (
    //             from m in _context.Mascotas
    //             join e in _context.Especies on m.IdEspecieFk equals e.Id
    //             where e.Nombre == "Felina"
    //             select new {
    //                 NombreMascota = m.Nombre,
    //                 Fecha = m.FechaNacimiento,
    //                 Especie= e.Nombre
    //             }
    //         ).ToListAsync();
    //     }


    //     public async Task<(int totalRegistros, IEnumerable<object> registros)> GetPetEspecie(int pageIndex, int pageSize, string search)
    //     {
    //         var query = (
    //             from m in _context.Mascotas
    //             join e in _context.Especies on m.IdEspecieFk equals e.Id
    //             where e.Nombre == "Felina"
    //             select new {
    //                 NombreMascota = m.Nombre,
    //                 Fecha = m.FechaNacimiento,
    //                 Especie= e.Nombre
    //             }
    //         );


    //         if (!string.IsNullOrEmpty(search))
    //         {
    //             query = query.Where(p => p.NombreMascota.ToLower().Contains(search));
    //         }


    //         query = query.OrderBy(p => p.NombreMascota);
    //         var totalRegistros = await query.CountAsync();
    //         var registros = await query
    //             .Skip((pageIndex - 1) * pageSize)
    //             .Take(pageSize)
    //             .ToListAsync();


    //         return (totalRegistros, registros);
    //     }


    //     //CONSULTA B-1: Listar todas las mascotas agrupadas por especie. SOSPECHOSA


    //     public async Task<IEnumerable<object>> GetPetGropuByEspe()
    //     {
    //         var objeto = from e in _context.Especies
    //                      join m in _context.Mascotas on e.Id equals m.IdEspecieFk into grupoEspecie
    //                      select new
    //                      {
    //                          Nombre = e.Nombre,
    //                          mascotica = grupoEspecie.Select(m => new
    //                          {
    //                              Nombre = m.Nombre,
    //                              Fecha = m.FechaNacimiento
    //                          }).ToList()


    //                      };
    //         return await objeto.ToListAsync();
    //     }


    //     public async Task<(int totalRegistros, IEnumerable<object> registros)> GetPetGropuByEspe(int pageIndex, int pageSize, string search)
    //     {
    //         var query = from e in _context.Especies
    //                      join m in _context.Mascotas on e.Id equals m.IdEspecieFk into grupoEspecie
    //                      select new
    //                      {
    //                          Nombre = e.Nombre,
    //                          mascotica = grupoEspecie.Select(m => new
    //                          {
    //                              Nombre = m.Nombre,
    //                              Fecha = m.FechaNacimiento
    //                          }).ToList()


    //                      };


    //         if (!string.IsNullOrEmpty(search))
    //         {
    //             query = query.Where(p => p.Nombre.ToLower().Contains(search));
    //         }


    //         query = query.OrderBy(p => p.Nombre);
    //         var totalRegistros = await query.CountAsync();
    //         var registros = await query
    //             .Skip((pageIndex - 1) * pageSize)
    //             .Take(pageSize)
    //             .ToListAsync();


    //         return (totalRegistros, registros);
    //     }


    //     //CONSULTA B-3 : Listar las mascotas que fueron atendidas por un determinado veterinario.
    //     public async Task<IEnumerable<object>> GetPetForVet()
    //     {
    //         var consulta =
    //         from e in _context.Citas
    //         join v in _context.Veterinarios on e.IdVeterinarioFk equals v.Id
    //         select new
    //         {
    //             Veterinario = v.Nombre,
    //             Mascotas = (from c in _context.Citas
    //                         join m in _context.Mascotas on c.IdMascotaFk equals m.Id
    //                         where c.IdVeterinarioFk == v.Id
    //                         select new
    //                         {
    //                             NombreMascota = m.Nombre,
    //                             FechaNacimiento = m.FechaNacimiento,
    //                         }).ToList()
    //         };


    //         return await consulta.ToListAsync();
    //     }


    //     public async Task<(int totalRegistros, IEnumerable<object> registros)> GetPetForVet(int pageIndex, int pageSize, string search)
    //     {
    //         var query = from e in _context.Citas
    //         join v in _context.Veterinarios on e.IdVeterinarioFk equals v.Id
    //         select new
    //         {
    //             Veterinario = v.Nombre,
    //             Mascotas = (from c in _context.Citas
    //                         join m in _context.Mascotas on c.IdMascotaFk equals m.Id
    //                         where c.IdVeterinarioFk == v.Id
    //                         select new
    //                         {
    //                             NombreMascota = m.Nombre,
    //                             FechaNacimiento = m.FechaNacimiento,
    //                         }).ToList()
    //         };


    //         if (!string.IsNullOrEmpty(search))
    //         {
    //             query = query.Where(p => p.Veterinario.ToLower().Contains(search));
    //         }


    //         query = query.OrderBy(p => p.Veterinario);
    //         var totalRegistros = await query.CountAsync();
    //         var registros = await query
    //             .Skip((pageIndex - 1) * pageSize)
    //             .Take(pageSize)
    //             .ToListAsync();


    //         return (totalRegistros, registros);
    //     }


    //     //CONSULTA B5: Listar las mascotas y sus propietarios cuya raza sea Golden Retriver


    //     public async Task<IEnumerable<object>> GetPetProRazaGoldenRetriever()
    //     {
    //         var objeto = from m in _context.Mascotas
    //                      join p in _context.Propietarios on m.IdPropietarioFk equals p.Id
    //                      join r in _context.Razas on m.IdRazaFk equals r.Id
    //                      where r.Nombre == "Golden Retriever"
    //                      select new
    //                      {
    //                          NombreMascota = m.Nombre,
    //                          NombrePropietario = p.Nombre,
    //                          Raza = r.Nombre
    //                      };
    //         return await objeto.ToListAsync();
    //     }


    //     public async Task<(int totalRegistros, IEnumerable<object> registros)> GetPetProRazaGoldenRetriever(int pageIndex, int pageSize, string search)
    //     {
    //         var query = from m in _context.Mascotas
    //                     join p in _context.Propietarios on m.IdPropietarioFk equals p.Id
    //                     join r in _context.Razas on m.IdRazaFk equals r.Id
    //                     where r.Nombre == "Golden Retriever"
    //                     select new
    //                     {
    //                         NombreMascota = m.Nombre,
    //                         NombrePropietario = p.Nombre,
    //                         Raza = r.Nombre
    //                     };


    //         if (!string.IsNullOrEmpty(search))
    //         {
    //             query = query.Where(p => p.NombreMascota.ToLower().Contains(search));
    //         }


    //         query = query.OrderBy(p => p.NombreMascota);
    //         var totalRegistros = await query.CountAsync();
    //         var registros = await query
    //             .Skip((pageIndex - 1) * pageSize)
    //             .Take(pageSize)
    //             .ToListAsync();


    //         return (totalRegistros, registros);
    //     }

    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Persistencia;

namespace Aplicacion.Repository
{
    public class PersonaRepository : GenericRepository<Persona>, IPersona
    {
        private readonly ApiJwtContext _context;

        public PersonaRepository(ApiJwtContext context) : base(context)
        {
            _context = context;
        }

        public override async Task<IEnumerable<Persona>> GetAllAsync()
        {
            return await _context.Personas
            .Include(p => p.TipoPersona)
            .Include(p => p.TipoDocumento)
            .Include(p => p.Rol)
            .ToListAsync();
        }

        public override async Task<Persona> GetByIdAsync(int id)
        {
            return await _context.Personas
            .Include(p => p.TipoPersona)
            .Include(p => p.TipoDocumento)
            .Include(p => p.Rol)
            .FirstOrDefaultAsync(p => p.Id == id);
        }


    }
}
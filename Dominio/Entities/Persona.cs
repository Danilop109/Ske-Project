using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Dominio.Entities
{
    public class Persona : BaseEntity
    {
        public string Nombre { get; set; }
        public string Documento {get; set;}
        public DateTime FechaRegistro {get; set;}
        public int IdTipoPersonaFk {get; set;}
        public TipoPersona TipoPersona {get; set;}
    }
}
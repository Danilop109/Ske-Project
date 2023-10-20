using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dominio.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Persistencia.Data.Configuration
{
    public class PersonaConfiguration : IEntityTypeConfiguration<Persona>
    {
        public void Configure(EntityTypeBuilder<Persona> builder)
        {
            builder.ToTable("persona");

            builder.Property(n => n.Nombre)
            .HasColumnName("Nombre")
            .HasColumnType("varchar")
            .IsRequired()
            .HasMaxLength(100);

            builder.Property(n => n.Documento)
            .HasColumnName("Documento")
            .HasColumnType("varchar")
            .IsRequired()
            .HasMaxLength(10);

            builder.Property(n => n.FechaRegistro)
            .HasColumnName("FechaRegistro")
            .HasColumnType("DateTime")
            .IsRequired();

            builder.HasOne(t => t.TipoPersona)
            .WithMany(t => t.Personas)
            .HasForeignKey(t => t.IdTipoPersonaFk);

        }
    }
}
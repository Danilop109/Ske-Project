using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dominio.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Persistencia.Data.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.ToTable("user");

            builder.Property(p => p.Id)
            .IsRequired();

            builder.Property(p => p.Username)
            .HasColumnName("username")
            .HasColumnType("varchar")
            .HasMaxLength(50)
            .IsRequired();


            builder.Property(p => p.Password)
            .HasColumnName("password")
            .HasColumnType("varchar")
            .HasMaxLength(255)
            .IsRequired();

            builder.Property(p => p.Email)
            .HasColumnName("email")
            .HasColumnType("varchar")
            .HasMaxLength(100)
            .IsRequired();

            builder
            .HasMany(p => p.Rols)
            .WithMany(r => r.Users)
            .UsingEntity<UserRol>(

                j => j
                .HasOne(pt => pt.Rol)
                .WithMany(t => t.UsersRols)
                .HasForeignKey(ut => ut.RolId),


                j => j
                .HasOne(et => et.Usuario)
                .WithMany(et => et.UsersRols)
                .HasForeignKey(el => el.UsuarioId),

                j =>
                {
                    j.ToTable("userRol");
                    j.HasKey(t => new { t.UsuarioId, t.RolId });

                });

            builder.HasMany(p => p.RefreshTokens)
            .WithOne(p => p.User)
            .HasForeignKey(p => p.UserId);

        //     public class ApplicationDbContext : DbContext
        // {
        //     public DbSet<Usuario> Usuarios { get; set; }
        //     public DbSet<Perfil> Perfiles { get; set; }

        //     protected override void OnModelCreating(ModelBuilder modelBuilder)
        //     {
        //         // Definir la relación uno a uno entre Usuario y Perfil
        //         modelBuilder.Entity<Usuario>()
        //             .HasOne(u => u.Perfil)
        //             .WithOne(p => p.Usuario)
        //             .HasForeignKey<Perfil>(p => p.UsuarioId);

        //         base.OnModelCreating(modelBuilder);
        //     }
        // }

        // public class Usuario
        // {
        //     public int Id { get; set; }
        //     public string Nombre { get; set; }

        //     // Propiedad de navegación para el perfil
        //     public Perfil Perfil { get; set; }
        // }

        // public class Perfil
        // {
        //     public int Id { get; set; }
        //     public string Descripcion { get; set; }

        //     // Propiedad de navegación inversa para el usuario
        //     public Usuario Usuario { get; set; }
        //     public int UsuarioId { get; set; } // Clave foránea para la relación
        // }
    }
}
}
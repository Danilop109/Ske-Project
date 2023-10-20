using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dominio.Entities;

namespace Dominio.Interfaces
{
    public interface IUser : IGenericRepository<User>
    {
        Task<User> GetByUsernameAsync(String username);
        Task<User> GetByRefreshTokenAsync(String username);
    }
}
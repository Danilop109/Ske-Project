using Api.Dtos;
using API.Dtos;
using AutoMapper;
using Dominio.Entities;

namespace Api.Profiles;
public class MappingProfiles : Profile
{
    public MappingProfiles()
    { 
        CreateMap<Rol,RolDto>().ReverseMap();
        CreateMap<User,UserDto>().ReverseMap();

    }
}

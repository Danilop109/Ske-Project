using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Api.Dtos;
using Api.Helpers.Errors;
using Api.Services;
using AutoMapper;
using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Api.Controllers
{
    [ApiVersion("1.0")]
    [ApiVersion("1.1")]
    public class UserController : BaseApiController
    {
        private readonly IUserService _userService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        public UserController(IUserService userService, IUnitOfWork unitOfWork, IMapper mapper)
        {
            _userService = userService;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]

    public async Task<ActionResult<IEnumerable<UserDto>>> Get()
    {
        var entidad = await _unitOfWork.Users.GetAllAsync();
        return _mapper.Map<List<UserDto>>(entidad);
    }

    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]

    public async Task<ActionResult<UserDto>> Get(int id)
    {
        var entidad = await _unitOfWork.Users.GetByIdAsync(id);
        if (entidad == null){
            return NotFound();
        }
        return _mapper.Map<UserDto>(entidad);
    }

    [HttpGet]
    [MapToApiVersion("1.1")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<Pager<UserDto>>> GetPagination([FromQuery] Params parametros)
    {
        var entidad = await _unitOfWork.Users.GetAllAsync(parametros.PageIndex, parametros.PageSize, parametros.Search);
        var listEntidad = _mapper.Map<List<UserDto>>(entidad.registros);
        return new Pager<UserDto>(listEntidad, entidad.totalRegistros, parametros.PageIndex, parametros.PageSize, parametros.Search);
    }

    [HttpPost]
    // [Authorize(Roles = "Administrador")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]

    public async Task<ActionResult<User>> Post(UserDto userDto)
    {
        var entidad = this._mapper.Map<User>(userDto);
        this._unitOfWork.Users.Add(entidad);
        await _unitOfWork.SaveAsync();
        if(entidad == null)
        {
            return BadRequest();
        }
        userDto.Id = entidad.Id;
        return CreatedAtAction(nameof(Post), new {id = userDto.Id}, userDto);
    }

    [HttpPut("{id}")]
    [Authorize(Roles = "Administrador")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]

    public async Task<ActionResult<UserDto>> Put(int id, [FromBody]UserDto userDto){
        if(userDto == null)
        {
            return NotFound();
        }
        var entidad = this._mapper.Map<User>(userDto);
        _unitOfWork.Users.Update(entidad);
        await _unitOfWork.SaveAsync();
        return userDto;
    }

    [HttpDelete("{id}")]
    [Authorize(Roles = "Administrador")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]

    public async Task<IActionResult> Delete(int id){
        var entidad = await _unitOfWork.Users.GetByIdAsync(id);
        if(entidad == null)
        {
            return NotFound();
        }
        _unitOfWork.Users.Remove(entidad);
        await _unitOfWork.SaveAsync();
        return NoContent();
    }



    [HttpPost("register")]
    // [Authorize(Roles = "Administrador")]
    public async Task<ActionResult> RegisterAsync(RegisterDto model)
    {
        var result = await _userService.RegisterAsync(model);
        return Ok(result);
    }

    [HttpPost("token")]
    public async Task<IActionResult> GetTokenAsync(LoginDto model)
    {
        var result = await _userService.GetTokenAsync(model);
        SetRefreshTokenInCookie(result.RefreshToken);
        return Ok(result);
    }

    [HttpPost("addrole")]
    // [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> AddRoleAsync(AddRoleDto model)
    {
        var result = await _userService.AddRoleAsync(model);
        return Ok(result);
    }

    [HttpPost("refresh-token")]
    // [Authorize]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = await _userService.RefreshTokenAsync(refreshToken);
        if (!string.IsNullOrEmpty(response.RefreshToken))
            SetRefreshTokenInCookie(response.RefreshToken);
        return Ok(response);
    }


    private void SetRefreshTokenInCookie(string refreshToken)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(10),
        };
        Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
    }
    
    }

    // [HttpGet]
    // [MapToApiVersion("1.0")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]


    // public async Task<ActionResult<IEnumerable<MascotaDto>>> Get()
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetAllAsync();
    //     return _mapper.Map<List<MascotaDto>>(entidad);
    // }


    // [HttpGet("{id}")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // [ProducesResponseType(StatusCodes.Status404NotFound)]


    // public async Task<ActionResult<MascotaDto>> Get(int id)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetByIdAsync(id);
    //     if (entidad == null){
    //         return NotFound();
    //     }
    //     return _mapper.Map<MascotaDto>(entidad);
    // }


    // [HttpGet]
    // [MapToApiVersion("1.1")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<Pager<MascotaDto>>> GetPagination([FromQuery] Params paisParams)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetAllAsync(paisParams.PageIndex, paisParams.PageSize, paisParams.Search);
    //     var listEntidad = _mapper.Map<List<MascotaDto>>(entidad.registros);
    //     return new Pager<MascotaDto>(listEntidad, entidad.totalRegistros, paisParams.PageIndex, paisParams.PageSize, paisParams.Search);
    // }
    // //CONSULTA 3
    // [HttpGet("GetPetEspecie")]
    // [MapToApiVersion("1.0")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<object>> GetPetEspecieConsulta3()
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetEspecie();
    //     var dto = _mapper.Map<IEnumerable<object>>(entidad);
    //     return Ok(dto);
    // }


    // [HttpGet("GetPetEspecie")]
    // [MapToApiVersion("1.1")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<Pager<object>>> GetPetEspecieConsulta3Pag([FromQuery] Params Parameters)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetEspecie(Parameters.PageIndex, Parameters.PageSize, Parameters.Search);
    //     var listEntidad = _mapper.Map<List<object>>(entidad.registros);
    //     return Ok(new Pager<object>(listEntidad, entidad.totalRegistros, Parameters.PageIndex, Parameters.PageSize, Parameters.Search));
    // }


    // //CONSULTA B-1
    // [HttpGet("GetPetGropuByEspe")]
    // [MapToApiVersion("1.0")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<object>> GetPetGropuByEspeConsultaB1()
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetGropuByEspe();
    //     var dto = _mapper.Map<IEnumerable<object>>(entidad);
    //     return Ok(dto);
    // }


    // [HttpGet("GetPetGropuByEspe")]
    // [MapToApiVersion("1.1")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<Pager<object>>> GetPetGropuByEspeConsultaB1Pag([FromQuery] Params Parameters)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetGropuByEspe(Parameters.PageIndex, Parameters.PageSize, Parameters.Search);
    //     var listEntidad = _mapper.Map<List<object>>(entidad.registros);
    //     return Ok(new Pager<object>(listEntidad, entidad.totalRegistros, Parameters.PageIndex, Parameters.PageSize, Parameters.Search));
    // }


    // //CONSULTA B-3
    // [HttpGet("GetPetForVet")]
    // [MapToApiVersion("1.0")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<object>> GetPetForVetConsultaB3()
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetForVet();
    //     var dto = _mapper.Map<IEnumerable<object>>(entidad);
    //     return Ok(dto);
    // }


    // [HttpGet("GetPetForVet")]
    // [MapToApiVersion("1.1")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<Pager<object>>> GetPetForVetConsultaB3Pag([FromQuery] Params Parameters)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetForVet(Parameters.PageIndex, Parameters.PageSize, Parameters.Search);
    //     var listEntidad = _mapper.Map<List<object>>(entidad.registros);
    //     return Ok(new Pager<object>(listEntidad, entidad.totalRegistros, Parameters.PageIndex, Parameters.PageSize, Parameters.Search));
    // }


    // //CONSULTA B-5
    // [HttpGet("GetPetProRazaGoldenRetriever")]
    // [MapToApiVersion("1.0")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<object>> GetPetProRazaGoldenRetrieverConsultaB5()
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetProRazaGoldenRetriever();
    //     var dto = _mapper.Map<IEnumerable<object>>(entidad);
    //     return Ok(dto);
    // }


    // [HttpGet("GetPetProRazaGoldenRetriever")]
    // [MapToApiVersion("1.1")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // public async Task<ActionResult<IEnumerable<object>>> GetPetProRazaGoldenRetrieverConsultab5([FromQuery] Params Parameters)
    // {
    //     var entidad = await _unitOfWork.Mascotas.GetPetProRazaGoldenRetriever(Parameters.PageIndex, Parameters.PageSize, Parameters.Search);
    //     var listEntidad = _mapper.Map<List<object>>(entidad.registros);
    //     return Ok(new Pager<object>(listEntidad, entidad.totalRegistros, Parameters.PageIndex, Parameters.PageSize, Parameters.Search));
    // }


    // [HttpPost]
    // [ProducesResponseType(StatusCodes.Status201Created)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]


    // public async Task<ActionResult<Mascota>> Post(MascotaDto mascotaDto)
    // {
    //     var entidad = this._mapper.Map<Mascota>(mascotaDto);
    //     this._unitOfWork.Mascotas.Add(entidad);
    //     await _unitOfWork.SaveAsync();
    //     if(entidad == null)
    //     {
    //         return BadRequest();
    //     }
    //     mascotaDto.Id = entidad.Id;
    //     return CreatedAtAction(nameof(Post), new {id = mascotaDto.Id}, mascotaDto);
    // }


    // [HttpPut("{id}")]
    // [ProducesResponseType(StatusCodes.Status200OK)]
    // [ProducesResponseType(StatusCodes.Status400BadRequest)]
    // [ProducesResponseType(StatusCodes.Status404NotFound)]


    // public async Task<ActionResult<MascotaDto>> Put(int id, [FromBody]MascotaDto mascotaDto){
    //     if(mascotaDto == null)
    //     {
    //         return NotFound();
    //     }
    //     var entidad = this._mapper.Map<Mascota>(mascotaDto);
    //     _unitOfWork.Mascotas.Update(entidad);
    //     await _unitOfWork.SaveAsync();
    //     return mascotaDto;
    // }


    // [HttpDelete("{id}")]
    // [ProducesResponseType(StatusCodes.Status204NoContent)]
    // [ProducesResponseType(StatusCodes.Status404NotFound)]


    // public async Task<IActionResult> Delete(int id){
    //     var entidad = await _unitOfWork.Mascotas.GetByIdAsync(id);
    //     if(entidad == null)
    //     {
    //         return NotFound();
    //     }
    //     _unitOfWork.Mascotas.Remove(entidad);
    //     await _unitOfWork.SaveAsync();
    //     return NoContent();
    // }

}
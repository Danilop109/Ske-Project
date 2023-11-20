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
    private readonly IUserService _Userservice;
    private readonly IUnitOfWork unitofwork;
    private readonly IMapper mapper;

    public UserController(IUserService Userservice, IUnitOfWork unitofwork, IMapper mapper)
    {
        this.unitofwork = unitofwork;
        this.mapper = mapper;
        _Userservice = Userservice;
    }
    [HttpGet]
/*     [Authorize(Roles = "Administrador")]
 */    [MapToApiVersion("1.0")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<IEnumerable<UserDto>>> Get()
    {
        var entidad = await unitofwork.Users.GetAllAsync();
        return mapper.Map<List<UserDto>>(entidad);
    }
    
    [HttpGet]
/*     [Authorize(Roles = "Administrador")]
 */    [MapToApiVersion("1.1")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<Pager<UserDto>>> GetPagination([FromQuery] Params paisParams)
    {
        var entidad = await unitofwork.Users.GetAllAsync(paisParams.PageIndex, paisParams.PageSize, paisParams.Search);
        var listEntidad = mapper.Map<List<UserDto>>(entidad.registros);
        return new Pager<UserDto>(listEntidad, entidad.totalRegistros, paisParams.PageIndex, paisParams.PageSize, paisParams.Search);
    }
    
    [HttpGet("{id}")]
/*     [Authorize(Roles = "Administrador")]
 */    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]

    public async Task<ActionResult<UserDto>> Get(int id)
    {
        var entidad = await unitofwork.Users.GetByIdAsync(id);
        if (entidad == null)
        {
            return NotFound();
        }
        return this.mapper.Map<UserDto>(entidad);
    }
    [HttpPost("register")]
/*     [Authorize(Roles = "Administrador")]
 */    public async Task<ActionResult> RegisterAsync(RegisterDto model)
    {
        var result = await _Userservice.RegisterAsync(model);
        return Ok(result);
    }

    [HttpPost("token")]
    public async Task<IActionResult> GetTokenAsync(LoginDto model)
    {
        var result = await _Userservice.GetTokenAsync(model);
        SetRefreshTokenInCookie(result.RefreshToken);
        return Ok(result);
    }
    
    [HttpPost("addrole")]
/*     [Authorize(Roles = "Administrador")]
 */    public async Task<IActionResult> AddRoleAsync(AddRoleDto model)
    {
        var result = await _Userservice.AddRoleAsync(model);
        return Ok(result);
    }

    [HttpPost("refresh-token")]
/*     [Authorize]
 */    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = await _Userservice.RefreshTokenAsync(refreshToken);
        if (!string.IsNullOrEmpty(response.RefreshToken))
            SetRefreshTokenInCookie(response.RefreshToken);
        return Ok(response);
    }


    [HttpPut("{id}")]
/*     [Authorize(Roles = "Administrador")]
 */    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]

    public async Task<ActionResult<UserDto>> Put(int id, [FromBody] UserDto entidadDto)
    {
        if (entidadDto == null)
        {
            return NotFound();
        }
        var entidad = this.mapper.Map<User>(entidadDto);
        unitofwork.Users.Update(entidad);
        await unitofwork.SaveAsync();
        return entidadDto;
    }

    [HttpDelete("{id}")]
/*     [Authorize(Roles = "Administrador")]
 */    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(int id)
    {
        var entidad = await unitofwork.Users.GetByIdAsync(id);
        if (entidad == null)
        {
            return NotFound();
        }
        unitofwork.Users.Remove(entidad);
        await unitofwork.SaveAsync();
        return NoContent();
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
}
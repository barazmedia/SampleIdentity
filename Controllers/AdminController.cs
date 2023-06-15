using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SampleIdentity.Models;

namespace SampleIdentity.Controllers
{
    //setting autorisasi hanya dapat diakses oleh user yang login dengan role admin
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        
        private readonly ILogger<AdminController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(ILogger<AdminController> logger,UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _userManager = userManager;
            _roleManager = roleManager;
        }


        public IActionResult ListRole()
        {
            var roles = _roleManager.Roles;
            return View(roles);
        }

        public async Task<IActionResult> EditUsersInRole(string roleId)
        {
            //mengirimkan parameter role id ke view
            ViewData["roleId"] = roleId;
            //mendapatkan data role berdasarkan parameter roleId
            var role = await _roleManager.FindByIdAsync(roleId);
            if(role == null)//melakukan pengecekan apakah role = null
            {
                ViewData["PesanError"]=$"<span class='alert alert-danger'>Role dengan id {roleId} tidak ditemukan </Span>";
                return View("NotFound");
            }
            else //jika role != null
            {
                //membuat list user ke dalam UserInRoleViewModel
                var model = new List<UserInRoleViewModel>();
                foreach(var user in _userManager.Users)
                {
                    var userInRoleViewModel = new UserInRoleViewModel{
                        UserId = user.Id,
                        UserName = user.UserName
                    };
                    //cek apakah user ada dalam role
                    if(await _userManager.IsInRoleAsync(user,role.Name))
                    {
                        //jika ada atau sudah terdaftar maka prop IsSelected = true
                        userInRoleViewModel.IsSelected = true;
                    }
                    else
                    {
                        userInRoleViewModel.IsSelected = false;
                    }
                    //tambahkan userInRoleViewModel ke List Model
                    model.Add(userInRoleViewModel);
                }
                return View(model);
            }
        }
        [HttpPost]
        public async Task<IActionResult> EditUsersInRole(List<UserInRoleViewModel> model, string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role == null)
            {
                ViewData["PesanError"]=$"<span class='alert alert-danger'>Role dengan id {roleId} tidak ditemukan </Span>";
                return View("NotFound");
            }
            for (int i = 0; i < model.Count; i++)
            {
                var user = await _userManager.FindByIdAsync(model[i].UserId);
                IdentityResult result = null;

                //jika selected terselect dan user tidak ada dalam role berarti di tambah......
                if(model[i].IsSelected && !(await _userManager.IsInRoleAsync(user, role.Name)))
                {
                    result = await _userManager.AddToRoleAsync(user,role.Name);
                }
                else if(!model[i].IsSelected && await _userManager.IsInRoleAsync(user, role.Name))
                {
                    result = await _userManager.RemoveFromRoleAsync(user, role.Name);
                }
                else
                {
                    continue;
                }
                //lakukan pengecekan 
                if(result.Succeeded)
                {
                    if(i < (model.Count - 1))
                    {
                        continue;
                    }
                    else
                    {
                        return RedirectToAction("EditRole",new {Id = roleId});
                    }
                }
            }
            return RedirectToAction("EditRole", new {Id = roleId});
        }

        //Membuat role **************************************************************************************************
        [HttpGet]
        public IActionResult CreateRole()
        {
            return View();
        }
        public async Task<IActionResult> CreateRole(CreateRoleViewModel model)
        {
            if(ModelState.IsValid)
            {
                IdentityRole identityRole = new IdentityRole{
                    Name = model.RoleName
                };
                IdentityResult result = await _roleManager.CreateAsync(identityRole);
                if(result.Succeeded)
                {
                    ViewData["pesan"]=$"<span class='alert alert-success'>Berhasil manambahkan role {model.RoleName}</span>";
                    return View();
                }
                foreach(IdentityError error in result.Errors)
                {
                    ModelState.AddModelError("",error.Description);
                }
            }
            return View();
        }
        //Membuat role **************************************************************************************************
        
        
        //Edit role **************************************************************************************************
        [HttpGet]
        public async Task<IActionResult> EditRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                ViewData["PesanError"]=$"<span class='alert alert-danger'>Data dengan id {id} tidak ditemukan</span>";
                return View("NotFound");
            }
            else
            {

            var model = new EditRoleViewModel{
                Id = role.Id,
                RoleName = role.Name
            };

            foreach(var user in _userManager.Users)
            {
                if(await _userManager.IsInRoleAsync(user,role.Name))
                {
                    model.Users.Add(user.UserName);
                }
            }
            return View(model);
            }
        }
        [HttpPost]
        public async Task<IActionResult> EditRole(EditRoleViewModel model)
        {
            var role = await _roleManager.FindByIdAsync(model.Id);
            if (role == null){
                ViewData["PesanError"]=$"<span class='alert alert-danger'>Data dengan id {model.Id} tidak ditemukan</span>";
                return View("NotFound");
            }
            else
            {
                role.Name = model.RoleName;
                var result = await _roleManager.UpdateAsync(role);
                if(result.Succeeded)
                {
                    return RedirectToAction("ListRole");
                }
                else
                {
                    foreach(var error in result.Errors)
                    {
                        ModelState.AddModelError("",error.Description);
                    }
                    return View(model);
                }
            }
        }
        //Edit role **************************************************************************************************
        
        public IActionResult Index()
        {
            var username = _userManager.GetUserName(User);
            ViewBag.username = username;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View("Error!");
        }
    }
}
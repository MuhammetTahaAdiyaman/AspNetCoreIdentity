using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Udemy.Identity.Entities;
using Udemy.Identity.Models;

namespace Udemy.Identity.Controllers
{
    [AutoValidateAntiforgeryToken]
    public class HomeController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<AppRole> _roleManager;
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<AppRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult AccessDenied()
        {
            return View();
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View(new UserCreateModel());
        }
        [HttpPost]
        public async Task<IActionResult> Create(UserCreateModel model)
        {
            if(ModelState.IsValid)
            {
               AppUser user = new AppUser()
               {
                   Gender = model.Gender,
                   UserName = model.Username,
                   Email = model.Email,
               };
               var identityResult = await _userManager.CreateAsync(user, model.Password);
               if (identityResult.Succeeded)
               {
                    var memberRole = await _roleManager.FindByNameAsync("Member");
                    if(memberRole == null)
                    {
                        await _roleManager.CreateAsync(new AppRole()
                        {
                            Name = "Member",
                            CreatedTime = DateTime.Now
                        });
                    }
                    await _userManager.AddToRoleAsync(user, "Member");
                    return RedirectToAction("Index","Home");
               }
                foreach (var error in identityResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult SignIn(string returnUrl)
        {
            return View(new UserSignInModel()
            {
                ReturnUrl = returnUrl
            });
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(UserSignInModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                var signInResult = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, true);
                if(signInResult.Succeeded)
                {
                    if (!string.IsNullOrWhiteSpace(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    var roles = await _userManager.GetRolesAsync(user);
                    if (roles.Contains("Admin"))
                    {
                        return RedirectToAction("AdminPanel", "Home");
                    }
                    else
                    {
                        return RedirectToAction("Panel", "Home");
                    }
                }
                else if (signInResult.IsLockedOut)
                {
                    var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                    ModelState.AddModelError("", $"hesabınız {(lockoutEnd.Value.UtcDateTime - DateTime.UtcNow).Minutes} dk askıya alınmıştır");
                }
                else
                {
                    var message = string.Empty;
                    if(user != null)
                    {
                        var failedCount = await _userManager.GetAccessFailedCountAsync(user);
                        message = $"{(_userManager.Options.Lockout.MaxFailedAccessAttempts-failedCount)} kez daha yanlış girerseniz hesabınız geçici olarak kilitlenecektir";
                    }
                    else
                    {
                        message = "Kullanıcı Adı veya Şifre hatalıdır!";
                    }
                    ModelState.AddModelError("", message);
                }
            }
            return View(model);
        }
        [Authorize]
        public IActionResult GetUserInfo()
        {
            //cookieden gelen kullanıcı bilgilerini görebiliriz.
            var userName = User.Identity.Name;
            var role = User.Claims.FirstOrDefault(x=>x.Type == ClaimTypes.Role);
            User.IsInRole("Member");
            return View();
        }

        [Authorize(Roles ="Admin")]
        public IActionResult AdminPanel()
        {
            return View();
        }

        [Authorize(Roles ="Member")]
        public IActionResult Panel()
        {
            return View();
        }
        
        [Authorize(Roles="Member")]
        public IActionResult MemberPage()
        {
            return View();
        }

        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}

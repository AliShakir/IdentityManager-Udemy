using IdentityManager_Udemy.Data;
using IdentityManager_Udemy.Models;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace IdentityManager_Udemy.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }
        [HttpGet]
        public IActionResult Index()
        {
            var userList = _db.ApplicationUsers.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userList)
            {
                var role = userRole.FirstOrDefault(u => u.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }
        [HttpGet]
        public IActionResult Edit(string userId)
        {
            var existingUser = _db.ApplicationUsers.FirstOrDefault(c => c.Id == userId);
            if (existingUser == null)
            {
                return NotFound();
            }
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userRole.FirstOrDefault(c=>c.UserId== existingUser.Id);
            if (role != null)
            {
                existingUser.RoleId = roles.FirstOrDefault(c => c.Id == role.RoleId).Id; 
            }
            existingUser.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });

            
            return View(existingUser);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            //if (ModelState.IsValid)
            //{
                var existingUser = _db.ApplicationUsers.FirstOrDefault(c => c.Id == user.Id);
                if (existingUser == null)
                {
                    return NotFound();
                }
                var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == existingUser.Id);
                if (userRole != null)
                {
                    var prevRole = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(c => c.Name).FirstOrDefault();
                    // Remove the previous role first...
                    await _userManager.RemoveFromRoleAsync(existingUser, prevRole);

                }
                // add new role
                await _userManager.AddToRoleAsync(existingUser, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                existingUser.Name = user.Name;
                _db.SaveChanges();
                TempData[SD.Success] = "User has been edited successfully.";
                return RedirectToAction(nameof(Index));
            //}

            user.RoleList = _db.Roles.Select(c => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = c.Name,
                Value = c.Id
            });

            return View(user);
        }
        public IActionResult LockUnlock(string userId)
        {
            var existingUser = _db.ApplicationUsers.FirstOrDefault(c => c.Id == userId);
            if (existingUser == null)
            {
                return NotFound();
            }
            if (existingUser.LockoutEnd != null && existingUser.LockoutEnd > DateTime.Now)
            {
                //If user already locked...We will Unlock him/her
                existingUser.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User has been unlocked successfully.";
            }
            else
            {
                //If user is not already locked...We will lock him/her
                existingUser.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User has locked successfully.";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public async Task<IActionResult> Delete(string userId)
        {
            var existingUser = _db.ApplicationUsers.FirstOrDefault(c => c.Id == userId);
            if (existingUser == null)
            {
                return NotFound();
            }
            _db.Users.Remove(existingUser);
            _db.SaveChanges();
            TempData[SD.Success] = "User has been deleted successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userId);
            
            if (user == null) { return NotFound();}

            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            var model = new UserClaimsViewModel()
            {
                UserId = userId,
            };
            foreach (Claim claim in ClaimStore.claimsList)
            {
                UserClaim userClaim = new UserClaim
                {
                    ClaimType = claim.Type
                };
                if(existingUserClaims.Any(c=>c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.Claims.Add(userClaim);
            }
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel userClaimsViewModel)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userClaimsViewModel.UserId);

            if (user == null) { return NotFound(); }

            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing claims";
                return View(userClaimsViewModel);
            }
            result = await _userManager.AddClaimsAsync(user,
                userClaimsViewModel.Claims.Where(c=>c.IsSelected).Select(c=> new Claim(c.ClaimType,c.IsSelected.ToString())));
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Erro while adding claims";
                return View(userClaimsViewModel);
            }
            TempData[SD.Success] = "Claims updated successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}

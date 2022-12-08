using IdentityManager_Udemy.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace IdentityManager_Udemy.Controllers
{
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(ApplicationDbContext db, 
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;

        }
        [HttpGet]
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }
        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if (String.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                var result = _db.Roles.FirstOrDefault(x => x.Id == id);
                return View(result);
            }
            
        }
        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole role)
        {
            if (await _roleManager.RoleExistsAsync(role.Name))
            {
                // Error
                TempData[SD.Error] = "Role already exists.";
                return RedirectToAction(nameof(Index));
            }
            if (String.IsNullOrEmpty(role.Id))
            {
                //Create Role
                await _roleManager.CreateAsync(new IdentityRole() { Name = role.Name});
                TempData[SD.Success] = "Role created successfully";
            }
            else
            {
                //Update Role
                var existingRole = _db.Roles.FirstOrDefault(c => c.Id == role.Id);
                if (existingRole == null)
                {
                    TempData[SD.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }
                existingRole.Name = role.Name;
                existingRole.NormalizedName = role.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(existingRole);
                TempData[SD.Success] = "Role updated successfully.";
            }
            return RedirectToAction(nameof(Index));

        }

        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var existingRole = _db.Roles.FirstOrDefault(c => c.Id == id);
            if (existingRole == null)
            {
                TempData[SD.Error] = "Role not found";
                return RedirectToAction(nameof(Index));
            }
            var roleAssigned = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if (roleAssigned > 0)
            {
                TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }
            await _roleManager.DeleteAsync(existingRole);
            TempData[SD.Success] = "Role deleted successfully.";
            return RedirectToAction(nameof(Index));

        }
    }
}

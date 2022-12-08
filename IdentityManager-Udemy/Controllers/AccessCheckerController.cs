using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager_Udemy.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        [HttpGet]
        [AllowAnonymous]
        // Accessible for all users
        public IActionResult AllAccess()
        {
            return View();
        }
        [HttpGet]
        // Accessible for logged in users
        public IActionResult AuthorizedAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize (Roles ="User")]
        // Accessible by users who have user role
        public IActionResult UserAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Roles = "User,Admin")]
        // Accessible by logged in users or admin
        public IActionResult UserOrAdminAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Policy = "UserAndAdmin")]
        // Accessible by logged in users or admin
        public IActionResult UserANDAdminAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize (Policy = "Admin")]        
        // Accessible by users who have admin role
        public IActionResult AdminAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Policy = "AdminCreateAccess")]
        // Accessible by admin users with a claim fo create to be true
        public IActionResult AdminCreateAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Policy = "AdminCreateEditDeleteAccess")]
        // Accessible by admin users with a claim of create/edit/delete 
        public IActionResult AdminCreateEditDeleteAccess()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Policy = "AdminCreateEditDeleteAccessOrSuperAdmin")]
        // Accessible by admin users with create edit and delete (and not or) or If the user is super admin
        public IActionResult AdminCreateEditDeleteAccessOrSuperAdmin()
        {
            return View();
        }
        [HttpGet]
        [Authorize(Policy = "AdminWithMoreThan1000Days")]
        // Only for Shakir
        public IActionResult OnlyShakir()
        {
            return View();
        }
    }
}

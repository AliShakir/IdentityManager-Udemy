using System.ComponentModel.DataAnnotations;

namespace IdentityManager_Udemy.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}

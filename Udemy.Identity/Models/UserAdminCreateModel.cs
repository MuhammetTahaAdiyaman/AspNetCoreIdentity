using System.ComponentModel.DataAnnotations;

namespace Udemy.Identity.Models
{
    public class UserAdminCreateModel
    {
        [Required(ErrorMessage = "Kullanıcı Adı Gereklidir")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Email Adresi Gereklidir")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Cinsiyet Bilgisi Gereklidir")]
        public string Gender { get; set; }  
    }
}

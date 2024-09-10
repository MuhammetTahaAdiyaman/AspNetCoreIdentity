using System.ComponentModel.DataAnnotations;

namespace Udemy.Identity.Models
{
    public class UserCreateModel
    {
        [Required(ErrorMessage ="Kullanıcı adı gereklidir!")]
        public string Username { get; set; }
        [Required(ErrorMessage ="Parola alanı gereklidir!")]
        public string Password { get; set; }
        [Compare("Password",ErrorMessage ="Parolalar eşleşmiyor!")]
        public string ConfirmPassword { get; set; }
        [EmailAddress(ErrorMessage ="Lütfen bir e-mail formatı giriniz!")]
        public string Email { get; set; }
        [Required(ErrorMessage ="Cinsiyet Gereklidir!")]
        public string Gender { get; set; }
    }
}

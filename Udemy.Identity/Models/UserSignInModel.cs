﻿using System.ComponentModel.DataAnnotations;

namespace Udemy.Identity.Models
{
    public class UserSignInModel
    {
        [Required(ErrorMessage ="Kullanıcı adı gereklidir")]
        public string Username { get; set; }
        [Required(ErrorMessage ="Parola gereklidir")]
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }
}

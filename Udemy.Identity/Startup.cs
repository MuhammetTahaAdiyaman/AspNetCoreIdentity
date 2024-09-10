using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Udemy.Identity.Context;
using Udemy.Identity.CustomDescriber;
using Udemy.Identity.Entities;

namespace Udemy.Identity
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            //uygulamamýza identity eklemek için.
            services.AddIdentity<AppUser, AppRole>(opt =>
            {
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequiredLength = 1;
                opt.Password.RequireLowercase = false;
                opt.Password.RequireUppercase = false;
                opt.Password.RequireDigit = false;
                //eðer isNotAllowed yani email doðrulanmasýný check etmesini istersek true yap;
                //opt.SignIn.RequireConfirmedEmail = false;
                //biz kilitli hesabýn açýlma süresini konfigüre edebilirriz aþaðýdaki kod ile
                //opt.Lockout.DefaultLockoutTimeSpan

                opt.Lockout.MaxFailedAccessAttempts = 3; //3 kez hatalý giriþ sonucu hesabý kilitlenecektir.

            }).AddErrorDescriber<CustomErrorDescriber>().AddEntityFrameworkStores<UdemyContext>();
            services.ConfigureApplicationCookie(opt =>
            {
                opt.Cookie.HttpOnly = true;  //"document.cookie" yapýnca data gelmesini engelliyor
                opt.Cookie.SameSite = SameSiteMode.Strict; //sadece ilgili domainde kullanýlýr
                opt.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; //Http ile gelirse http ile, https ile gelirse https ile çalýþþsýn anlamýndadýr
                opt.Cookie.Name = "UdemyCookie";
                opt.ExpireTimeSpan = TimeSpan.FromDays(25); //cookienin belirli süre ayakta kalmasýný istiyorum bunun için kullanýrýz genellikle sitelerde 40-60 gün
                opt.LoginPath = new PathString("/Home/SignIn"); //biz giriþ yapmadan yetkisiz yere eriþmek istediðimizde /Account/Login'e yönlendiriyordu artýk istediðimiz yani belirttiðimiz yere yönlendirecek.
                opt.AccessDeniedPath = new PathString("/Home/AccessDenied"); //artýk Account/AccessDenied deðil de Home/AccessDenied'a yönlendirecek.
            });
            services.AddControllersWithViews();
            services.AddDbContext<UdemyContext>(opt =>
            {
                opt.UseSqlServer("server=TAHA\\SQLEXPRESS; database=IdentityDb; integrated security = true");
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseStaticFiles();
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(),"node_modules")),
                RequestPath = "/node_modules"
            });
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}

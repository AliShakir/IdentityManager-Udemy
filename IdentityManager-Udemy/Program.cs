

using IdentityManager_Udemy.Authorize;
using IdentityManager_Udemy.Data;
using IdentityManager_Udemy.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

//builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ApplicationDbContext>();
//
builder.Services.AddIdentity<IdentityUser,IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
//
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();
//
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequiredLength = 5;
    opt.Password.RequireLowercase = true;
    opt.Lockout.DefaultLockoutTimeSpan= TimeSpan.FromSeconds(30);
    opt.Lockout.MaxFailedAccessAttempts = 5;
});
builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = "1567779000311859";
    options.AppSecret = "863926b767f7b8905fdb5592bb197935";
});
//
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
    options.AddPolicy("AdminCreateAccess", policy => policy.RequireRole("Admin").RequireClaim("create","True"));

    options.AddPolicy("AdminCreateEditDeleteAccess", policy => policy.RequireRole("Admin").RequireClaim("create", "True")
    .RequireClaim("edit","True").RequireClaim("delete", "True"));
    
    options.AddPolicy("AdminCreateEditDeleteAccessOrSuperAdmin", policy => policy.RequireAssertion(context => (
        context.User.IsInRole("Admin") && context.User.HasClaim(c =>c.Type =="Create" && c.Value=="True")
        && context.User.HasClaim(c=> c.Type == "Edit" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )|| context.User.IsInRole("SuperAdmin")));

    options.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
    options.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
});
//
builder.Services.AddScoped<IAuthorizationHandler,AdminWithMoreThan1000DasyHandler>();
//
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
//
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
});
//
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

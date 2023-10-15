namespace MonitoringService
{
    public class ApplicationUser
    {
        public ApplicationUser()
        {
        }

        public ApplicationUser(string email, string password)
        {
            Email = email;
            Password = password;
        }
        public string Email { get; set;}
        public string Password { get; set;}
    }
}
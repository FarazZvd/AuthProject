using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MonitoringService
{
    internal class InMemoryUserStore
    {
        private static List<ApplicationUser> Users;

        public InMemoryUserStore()
        {
            Users = new List<ApplicationUser>();
        }

        public static bool AuthenticateUser(ApplicationUser user)
        {
            if (user.Email == null || user.Password == null) 
            {
                throw new Exception("Invalild credentials!");
            }
            return Users.Any(userCopy => userCopy.Email == user.Email);
        }

        public static void AddUser(ApplicationUser user) 
        {
            Users.Add(user);
        }

        public static ApplicationUser GetUser(ApplicationUser user)
        {
            throw new NotImplementedException("Not needed yet as user info is already retrieved from AuthService while needed");
        }
    }
}

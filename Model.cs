using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace secu
{
    public class PasswordManagerContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Tag> Tags { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=passwordManager.db");
        }
    }

    public class User
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string MasterPassword { get; set; }
        public string Salt { get; set; }

        //public List<Tag> Tags { get; set; }

    }

    public class Tag
    {
        public int TagId { get; set; }
        public string TagName { get; set; }
        public string Password { get; set; } // L'iv est stocke devant le password avec le separateur |

        public int UserId { get; set; }
        //public User User { get; set; }
    }
}
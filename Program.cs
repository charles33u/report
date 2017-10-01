using System;

namespace secu
{
    public class Program
    {
        private static PasswordManager passwordManager = new PasswordManager();

        public static void Main(string[] args)
        {
            switch (args[0])
            {
                case "-r":
                    bool outRegistrer = passwordManager.Register(args[1], args[2]);
                    WriteOutput(outRegistrer);
                    break;
                case "-a":
                    bool outAdd = passwordManager.AddTag(args[1], args[2], args[3], args[4]);
                    WriteOutput(outAdd);
                    break;
                case "-g":
                    string outGet = passwordManager.GetPassByTag(args[1], args[2], args[3]);
                    Console.WriteLine(outGet);
                    break;
                case "-d":
                    bool outDelete = passwordManager.DeleteTag(args[1], args[2], args[3]);
                    WriteOutput(outDelete);
                    break;
                case "-t":
                    if (args.Length == 2)
                    {
                        string masterpassword = passwordManager.DisplayMaster(args[1]);
                        Console.WriteLine(masterpassword);
                        break;
                    }
                    else
                    {
                        string password = passwordManager.DisplayTagPassword(args[1], args[2]);
                        Console.WriteLine(password);
                        break;
                    }
                case "--GEMdp":
                    Help();
                    break;
                default:
                    break;
            }
            //DebugDb();
        }

        /* Methodes auxiliere d'affichage */

        private static void WriteOutput(bool condition)
        {
            if (condition)
            {
                Console.WriteLine("OK");
            }
            else
            {
                Console.WriteLine("ERROR");
            }
        }

        private static void Help()
        {
            Console.WriteLine("***Bienvenue sur GEMdp***\n");
            Console.WriteLine("Commandes de GEMdp");
            Console.WriteLine("  dotnet run -r <username> <masterpassword>                    S'enregistrer sur l'application");
            Console.WriteLine("  dotnet run -a <username> <masterpassword> <tag> <password>   Ajouter un mot de passe associé au tag");
            Console.WriteLine("  dotnet run -g <username> <masterpassword> <tag>              Recuperer le mot de passe du tag");
            Console.WriteLine("  dotnet run -d <username> <masterpassword> <tag>              Supprimer le tag et son mot de passe");
            Console.WriteLine("  dotnet run -t <username>                                     Affiche le masterpassword hashe et le sel cryptographique SALT:HASH");
            Console.WriteLine("  dotnet run -t <username> <tag>                               Affiche la version chiffree du mot de passe du tag");
        }

        /* Methodes de debug */

        public static void DebugDb()
        {
            using (var db = new PasswordManagerContext())
            {
                Console.WriteLine("/***Begin Debug");
                Console.WriteLine("  Utilisateurs dans la base : ");
                foreach (var user in db.Users)
                {
                    Console.WriteLine(" - {0} - {1}", user.UserId, user.UserName);
                }
                Console.WriteLine("/***End Debug");
            }
        }

    }
}
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.IO;
namespace secu
{
    class PasswordManager
    {
        public bool Register(string username, string masterpassword)
        {
            using (var db = new PasswordManagerContext())
            {
                byte[] salt = GenerateSalt();

                db.Users.Add(new User
                {
                    UserName = username,
                    MasterPassword = Convert.ToBase64String(EncryptMasterPassword(masterpassword, salt)),
                    Salt = Convert.ToBase64String(salt)
                });
                var count = db.SaveChanges();
                //Console.WriteLine("{0} records saved to database", count);
                return (count > 0);
            }

        }

        public bool AddTag(string username, string masterpassword, string tagname, string tagpassword)
        {
            using (var db = new PasswordManagerContext())
            {
                // On authentifie l'utilisateur
                User user = Authentify(username, masterpassword);
                if (user != null)
                {
                    // On recupere un objet aes
                    //AesManaged aes = GetAES(user);

                    // Creation de la chaine iv + tagpassword chiffre
                    byte[] save = EncrypTagPassword(tagpassword, user);

                    //byte[] save = new byte[aes.IV.Length + encryptedpass.Length];
                    //aes.IV.CopyTo(save, 0);
                    //encryptedpass.CopyTo(save, aes.IV.Length);

                    // On ajoute le tag et le mot de passe
                    db.Tags.Add(new Tag
                    {
                        TagName = tagname,
                        Password = Convert.ToBase64String(save),
                        UserId = user.UserId
                    });
                    var count = db.SaveChanges();
                    //Console.WriteLine("{0} records saved to database", count);
                    return (count > 0);
                }
                return false;
            }
        }

        public string GetPassByTag(string username, string masterpassword, string tag)
        {
            using (var db = new PasswordManagerContext())
            {
                // On authentifie l'utilisateur
                User user = Authentify(username, masterpassword);
                Tag tagUser = null;
                if (user != null)
                {
                    // On recupere le tag
                    foreach (var t in db.Tags)
                    {
                        if (t.TagName == tag && t.UserId == user.UserId)
                        {
                            tagUser = db.Tags.Find(t.TagId);
                        }
                    }
                    if (tagUser != null)
                    {
                        // On recupere un objet aes
                        //AesManaged aes = GetAES(user, tagUser.Password);
                        // On decrypte le mot de passe pour le retrouner en clair
                        return DecryptTagPassword(tagUser.Password, user);
                    }
                }
                return "ERROR";
            }
        }

        public bool DeleteTag(string username, string masterpassword, string tag)
        {
            using (var db = new PasswordManagerContext())
            {
                // On authentifie l'utilisateur
                User user = Authentify(username, masterpassword);
                Tag tagUser = null;
                if (user != null)
                {
                    // On recupere le tag
                    foreach (var t in db.Tags)
                    {
                        if (t.TagName == tag && t.UserId == user.UserId)
                        {
                            tagUser = db.Tags.Find(t.TagId);
                        }
                    }
                    if (!(tagUser == null))
                    {
                        // On supprime le tag et son mot de passe
                        db.Tags.Remove(tagUser);
                        var count = db.SaveChanges();
                        //Console.WriteLine("{0} records removed from database", count);
                        return (count > 0);
                    }
                }
                return false;
            }
        }

        public string DisplayMaster(string username)
        {
            // Recuperation des informations de l'utilisateur stocke en base
            User user = null;
            using (var db = new PasswordManagerContext())
            {
                foreach (var u in db.Users)
                {
                    if (u.UserName == username)
                    {
                        user = db.Users.Find(u.UserId);
                    }
                }
            }
            if (user != null)
            {
                return user.Salt + ":" + user.MasterPassword;
            }
            return "ERROR";
        }

        public string DisplayTagPassword(string username, string tag)
        {
            // Recuperation de l'utilisateur
            User user = null;
            Tag tagUser = null;
            using (var db = new PasswordManagerContext())
            {
                foreach (var u in db.Users)
                {
                    if (u.UserName == username)
                    {
                        user = db.Users.Find(u.UserId);
                    }
                }
                if (user != null)
                {
                    // On recupere le tag
                    foreach (var t in db.Tags)
                    {
                        if (t.TagName == tag && t.UserId == user.UserId)
                        {
                            tagUser = db.Tags.Find(t.TagId);
                        }
                    }
                    if (!(tagUser == null))
                    {
                        // Separer l'iv du mot de passe ? 
                        return tagUser.Password;
                    }
                }
                return "ERROR";
            }
        }

        private byte[] GenerateSalt()
        {
            // Generation du sel
            byte[] salt = new byte[16];
            Random random = new Random();
            random.NextBytes(salt);
            return salt;
        }

        private byte[] EncryptMasterPassword(string masterpassword, byte[] salt)
        {
            // Conversion du masterpassword en byte
            byte[] pass = Encoding.ASCII.GetBytes(masterpassword);

            // On ajoute le sel au mot de passe
            byte[] save = new byte[pass.Length + salt.Length];
            Array.ConstrainedCopy(pass, 0, save, 0, pass.Length);
            Array.ConstrainedCopy(salt, 0, save, pass.Length, salt.Length);

            // Hashage du mot de passe avec le sel
            SHA256Managed sha = new SHA256Managed();
            byte[] hash = sha.ComputeHash(save);

            return hash;
        }

        //private AesManaged GetAES(User user)
        //{
        //    using (AesManaged aes = new AesManaged())
        //    {
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.Zeros;
        //        aes.GenerateIV();
        //        KeySizes[] ks = aes.LegalKeySizes;
        //        KeySizes k = ks[aes.LegalKeySizes.Length - 1];   // 256 ?

        //        // Conversion du sel
        //        byte[] salt = Convert.FromBase64String(user.Salt);

        //        // Generation de la cle AES
        //        byte[] key = KeyDerivation.Pbkdf2(user.MasterPassword, salt, KeyDerivationPrf.HMACSHA256, 10000, k.MaxSize / 8);
        //        aes.Key = key;

        //        return aes;
        //    }
        //}

        //private AesManaged GetAES(User user, string tagpassword)
        //{
        //    using (AesManaged aes = new AesManaged())
        //    {
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.Zeros;

        //        // Recuperation de l'iv stocke avec le mot de passe
        //        int ivlenght = aes.IV.Length;
        //        byte[] ivpass = Convert.FromBase64String(tagpassword);
        //        byte[] iv = new byte[aes.IV.Length];
        //        Array.ConstrainedCopy(ivpass, 0, iv, 0, aes.IV.Length);

        //        KeySizes[] ks = aes.LegalKeySizes;
        //        KeySizes k = ks[aes.LegalKeySizes.Length - 1];   // 256 ?

        //        // Conversion du sel
        //        byte[] salt = Convert.FromBase64String(user.Salt);

        //        // Generation de la cle AES
        //        byte[] key = KeyDerivation.Pbkdf2(user.MasterPassword, salt, KeyDerivationPrf.HMACSHA256, 10000, k.MaxSize / 8);
        //        aes.Key = key;

        //        return aes;
        //    }
        //}

        private byte[] EncrypTagPassword(string tagpassword, User user)
        {
            using (AesManaged aes = new AesManaged())
            {
                //aes.GenerateIV();
                KeySizes[] ks = aes.LegalKeySizes;
                KeySizes k = ks[aes.LegalKeySizes.Length - 1];   // 256 ?

                // Conversion du sel
                byte[] salt = Convert.FromBase64String(user.Salt);

                // Generation de la cle AES
                byte[] key = KeyDerivation.Pbkdf2(user.MasterPassword, salt, KeyDerivationPrf.HMACSHA256, 10000, k.MaxSize / 8);
                aes.Key = key;

                byte[] tagpasswordencrypted;

                // Chiffrement du mot de passe
                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(tagpassword);
                            }
                            tagpasswordencrypted = msEncrypt.ToArray();
                            byte[] save = new byte[aes.IV.Length + tagpasswordencrypted.Length];
                            aes.IV.CopyTo(save, 0);
                            tagpasswordencrypted.CopyTo(save, aes.IV.Length);
                            return save;
                        }
                    }
                }
            }
        }

        private string DecryptTagPassword(string tagpassword, User user)
        {
            using (AesManaged aes = new AesManaged())
            {
                // Recuperation de l'iv stocke avec le mot de passe
                int ivlenght = aes.IV.Length;
                byte[] ivpass = Convert.FromBase64String(tagpassword);
                byte[] iv = new byte[aes.IV.Length];
                Array.ConstrainedCopy(ivpass, 0, iv, 0, aes.IV.Length);
                aes.IV = iv;

                KeySizes[] ks = aes.LegalKeySizes;
                KeySizes k = ks[aes.LegalKeySizes.Length - 1];   // 256 ?

                // Conversion du sel
                byte[] salt = Convert.FromBase64String(user.Salt);

                // Generation de la cle AES
                byte[] key = KeyDerivation.Pbkdf2(user.MasterPassword, salt, KeyDerivationPrf.HMACSHA256, 10000, k.MaxSize / 8);
                aes.Key = key;

                // Conversion du tagpassword
                byte[] ivpassword = Convert.FromBase64String(tagpassword);

                // On enlève l'iv
                byte[] password = new byte[ivpassword.Length - aes.IV.Length];
                Array.ConstrainedCopy(ivpassword, aes.IV.Length, password, 0, ivpassword.Length - aes.IV.Length);

                string decryptedPassword = null;

                // Dechiffrement du mot de passe
                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream msDecrypt = new MemoryStream(password))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                decryptedPassword = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
                return decryptedPassword;
            }
        }

        private User Authentify(string username, string masterpassword)
        {
            // Recuperation des informations de l'utilisateur stocke en base
            User user = null;
            using (var db = new PasswordManagerContext())
            {
                foreach (var u in db.Users)
                {
                    if (u.UserName == username)
                    {
                        user = db.Users.Find(u.UserId);
                    }
                }
            }
            // Decodage du sel cryptographique stocke en base
            byte[] salt = Convert.FromBase64String(user.Salt);

            // Hashage de mot de passe a verifier
            byte[] hash = EncryptMasterPassword(masterpassword, salt);

            // Conversion du hash en base64
            string hash64 = Convert.ToBase64String(hash);

            // Comparaison du hash du mot de passe a verifier et du mot de passe stocke en base
            if (hash64.Equals(user.MasterPassword))
            {
                return user;
            }
            else
            {
                return null;
            }
        }
    }
}

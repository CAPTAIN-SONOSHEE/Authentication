using Dapper;
using Microsoft.Data.SqlClient;
using System.Data;

namespace Authentication.Model
{
    public class UtilisateurRepo
    {
        private readonly string ConnectionString;

        readonly IConfiguration? _configuration;

        public UtilisateurRepo(IConfiguration configuration)
        {
            _configuration = configuration;
            ConnectionString = configuration.GetConnectionString("SQL");
        }




        public void Create(UtilisateurEntity utilisateur)
        {
            try
            {
                using (IDbConnection db = new SqlConnection(ConnectionString))
                {
                    string query = "INSERT INTO Utilisateur (nom_utilisateur, email, mot_de_passe, salt) " +
                                   "VALUES (@NomUtilisateur, @Email, @MotDePasse, @Salt)";
                    db.Execute(query, utilisateur);
                }
            }catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public async Task<int?> GetIDAsync(string email)
        {
            using (IDbConnection db = new SqlConnection(ConnectionString))
            {
                string query = "Select Id from Utilisateur where email = @Email";
                try
                {
                    return await db.QuerySingleOrDefaultAsync<int>(query, new { Email = email });
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        }

        public async Task<string?> GetPasswordAsync(string email)
        {
            using (IDbConnection db = new SqlConnection(ConnectionString))
            {
                string query = "SELECT mot_de_passe FROM Utilisateur WHERE email = @Email"; // Utilisation de paramètre
                try
                {
                    // Le type de retour doit correspondre à celui de la colonne en BDD.
                    return await db.QuerySingleOrDefaultAsync<string>(query, new { Email = email });
                }
                catch (Exception e)
                {
                    // Gestion des erreurs plus efficace
                    // Log ou lancez l'exception selon votre choix
                    return null;
                }
            }
        }

        public async Task<string?> GetSaltAsync(string email)
        {
            using (IDbConnection db = new SqlConnection(ConnectionString))
            {
                string query = "SELECT salt FROM Utilisateur WHERE email = @Email"; // Utilisation de paramètre
                try
                {
                    // Le type de retour doit correspondre à celui de la colonne en BDD.
                    return await db.QuerySingleOrDefaultAsync<string>(query, new { Email = email });
                }
                catch (Exception e)
                {
                    // Gestion des erreurs plus efficace
                    // Log ou lancez l'exception selon votre choix
                    return null;
                }
            }
        }

    }
}

namespace Authentication.Model
{
    public class UtilisateurEntity
    {
        public int Id { get; set; }
        public string NomUtilisateur { get; set; }
        public string Email { get; set; }
        public string MotDePasse { get; set; }
        public string Salt { get; set; }
    }
}

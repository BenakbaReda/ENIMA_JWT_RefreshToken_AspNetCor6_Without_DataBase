namespace Enima_AuthJwt
{
    public static  class DataManager  
    {
        public static IDictionary<string, string> users = new Dictionary<string, string>
        {
            { "test1", "password1" },
            { "test2", "password2" }
        };

        public static IDictionary<string, string> UsersRefreshTokens  = new Dictionary<string, string>();

 
 
        
        
    }



}
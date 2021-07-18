using System.Collections.Generic;

namespace jwt.api.Configuration
{
    public class AuthResult
    {
        public string Token { get; set; }
        public bool IsAuthenticated { get; set; }
        public List<string> Errors { get; set; }

    }
}
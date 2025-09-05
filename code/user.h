#ifndef USER_H
#define USER_H

#define USERNAME_LEN 32
#define PASSWORD_LEN 32
#define HASH_HEX_LEN 64 //sha 256 digest 32 bytes, stored in hex is 64
#define EMAIL_LEN 64
#define TOKEN_LEN 32

#include <string>

class User {
    private:
        std::string email;
        std::string username;
        std::string token;
        std::string password;
        int lmid;

    public:
        User();
        User(const char email[EMAIL_LEN],const char username[USERNAME_LEN],const char password[HASH_HEX_LEN],const char token[TOKEN_LEN],const int lmid);

        std::string getUsername()const;
        std::string getPassword()const;
        std::string getToken()const;
        std::string getEmail()const;
        int getLmid()const;

        void setUsername(const char username[USERNAME_LEN]);
        void setPassword(const char password[HASH_HEX_LEN]);
        void setToken(const char token[TOKEN_LEN]);
        void setEmail(const char email[EMAIL_LEN]);
        void setLmid(const int lmid);

        bool verifyToken(std::string token)const;
    
};

#endif

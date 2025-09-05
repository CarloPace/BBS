#include "user.h"
#include <cstring>

User::User(){
    this->username="xxxx";
    this->password="xxxx";
    this->token="xxxx";
    this->email="xxxx";
    this->lmid=0;
}
User::User(const char email[EMAIL_LEN],const char username[USERNAME_LEN],const char password[PASSWORD_LEN],const char token[TOKEN_LEN],const int lmid){
    this->username=username;
    this->password=password;
    this->email=email;
    this->token=token;
    this->lmid=lmid;
}

std::string User::getUsername() const {
    return this->username;
}
std::string User::getPassword() const {
    return this->password;
};

std::string User::getToken() const {
    return this->token;
};

std::string User::getEmail() const {
    return this->email;
};

int User::getLmid() const{
    return this->lmid;
}

bool User::verifyToken(std::string token) const {
    if(this->token.compare(token)==0)
        return true;
    return false;
}


void User::setUsername(const char username[USERNAME_LEN]) {
    this->username=username;
};

void User::setPassword(const char password[HASH_HEX_LEN]) {
    //include salting and freshness
    this->password=password;
};

void User::setToken(const char token[TOKEN_LEN]) {
    //include salting and freshness
    this->token=token;
};

void User::setEmail(const char email[EMAIL_LEN]) {
    //include salting and freshness
    this->email=email;
};

void User::setLmid(const int lmid){
    this->lmid=lmid;
}

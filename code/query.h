#ifndef QUERY_H
#define QUERY_H

#include <string>
#include <cstring>
#include <hiredis/hiredis.h>



redisReply* retrievePasswordOfUser(redisContext *c,const std::string& username) {   

    return (redisReply*)redisCommand(c, "HGET USER:%s password",username.c_str());
}


redisReply* createUser(redisContext *c,const std::string& username,const std::string& email,const std::string& password) {   

    return (redisReply*)redisCommand(c, "HSET USER:%s email %s password %s",username.c_str(),email.c_str(),password.c_str());
}


redisReply* createEmailKey(redisContext *c,const std::string& email) {   

    return (redisReply*)redisCommand(c, "SET EMAILS:%s 1",email.c_str());
}


redisReply* checkAlredyUsedEmail(redisContext *c,const std::string& email) {   

    return (redisReply*)redisCommand(c, "EXISTS EMAILS::%s",email.c_str());
}

redisReply* checkUsernameAvailable(redisContext *c,const std::string& username) {   

    return (redisReply*)redisCommand(c, "EXISTS USER::%s",username.c_str());
}

redisReply* addMessage(redisContext *c, int mid, const std::string& author, const std::string& title, const std::string& body) {
    
    std::string key = "MESSAGE:" + std::to_string(mid);

    return (redisReply*)redisCommand(c, "HSET %s author %s title %s body %s",
                                      key.c_str(),
                                      author.c_str(),
                                      title.c_str(),
                                      body.c_str());
}


redisReply* incrementMid(redisContext *c) {
    
    return (redisReply*)redisCommand(c, "INCR MID");
                                      
}


redisReply* retrieveLastMid(redisContext *c) {
    
    return (redisReply*)redisCommand(c, "GET MID");
                                      
}


redisReply* retrieveMessageByMid(redisContext *c,const std::string& mid) {
    
    return (redisReply*)redisCommand(c, "HGETALL MESSAGE:%s",mid.c_str());
                                      
}




#endif

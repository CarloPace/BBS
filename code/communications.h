#ifndef COMMUNICATIONS_H
#define COMMUNICATIONS_H

#include <string>
#include <iostream> 
#include <sstream> 
#include <vector> 
#include <stdlib.h>


#define COMM_ERROR 0
#define LOGIN_COMM 1
#define LOGIN_FAILED 12
#define LOGOUT_COMM 2
#define LOGOUT_FAILED 3
#define SIGNUP_COMM 4
#define SIGNUP_ERR 5
#define ADDMESS_COMM 6
#define ADDMESS_ERR 7
#define RTVMESS_COMM 8
#define RTVMESS_ERR 9
#define RTVNMESS_COMM 10
#define RTVNMESS_ERR 11
#define TOKEN_MISMATCH 35
#define SIGNUP_ERR_USERNAME_NOT_AVAILABLE 36
#define SIGNUP_ERR_EMAIL_AU 37
#define COMM_OK 200
#define OTPVERIFY_COMM 12
#define OTPVERIFY_FAILED 13
#define SIGNUP_OTP_REQUEST 333
#define CLOSE_CONN_COMM 999


#define COMMUNICATION_SIZE 257

#define COMM_BUFFER_SIZE 1025

typedef struct communicationsData{
    int code;
    int mid;
    int cycle;
    std::string otp;
    std::string email;
    std::string token;
    std::string username;
    std::string password;
    std::string title;
    std::string author;
    std::string body;
    
}communicationsData;













///***************************************************************

//LOGIN

std::string loginCom(std::string username,std::string password){
    return "Login\x1F\x1E"+username+"\x1F\x1E"+password;
};

std::string loginAck(std::string username,std::string token,int lmid){
    return "200\x1F\x1E"+username+"\x1F\x1E"+"Login"+"\x1F\x1EToken\x1F\x1E"+token+"\x1F\x1Elmid\x1F\x1E"+std::to_string(lmid);
}
std::string failedLoginAck(std::string username){
    return "275\x1F\x1E"+username+"\x1F\x1E"+"Login";
}

int readLoginAck(char communication[COMMUNICATION_SIZE],communicationsData *dataOut){
    std::string message(communication);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));

    if (tokens.empty()) {
        return COMM_ERROR;
    }

    if(tokens[0].compare("200")==0&&tokens[2].compare("Login")==0){
        dataOut->username=tokens[1];
        dataOut->token=tokens[4];
        dataOut->mid=atoi(tokens[6].c_str());
        return COMM_OK;
    }
    if(tokens[0].compare("275")==0&&tokens[2].compare("Login")==0){
        return LOGIN_FAILED;
    }
    return COMM_ERROR;
}

///***************************************************************

//LOGOUT

std::string logoutCom(std::string username,std::string token){
    return "Logout\x1F\x1E"+username+"\x1F\x1E"+token;
};

std::string successLogoutAck(std::string username){
    return "200\x1F\x1E"+username+"\x1F\x1E"+"Logout";
}
std::string failedLogoutAck(std::string username){
    return "201\x1F\x1E"+username+"\x1F\x1E"+"Logout";
}

int readLogoutAck(char communication[COMMUNICATION_SIZE]){
    std::string message(communication);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));

    if (tokens.empty()) {
        return COMM_ERROR;
    }

    if(tokens[0].compare("200")==0&&tokens[2].compare("Logout")==0)
        return COMM_OK;
    if(tokens[0].compare("201")==0&&tokens[2].compare("Logout")==0)
        return LOGOUT_FAILED;

    return COMM_ERROR;
}

///***************************************************************

//CLOSE_COMM

std::string closeConnCom(std::string username,std::string token){
    return "CloseConn\x1F\x1E"+username+"\x1F\x1E"+token;
};

///***************************************************************

//SIGN-UP

std::string signupCom(std::string email,std::string username,std::string password){
    return "Signup\x1F\x1E"+email+"\x1F\x1E"+username+"\x1F\x1E"+password;
}
std::string otpVerifyComm(std::string email,std::string username,std::string otp){
    return "OtpVerify\x1F\x1E"+email+"\x1F\x1E"+username+"\x1F\x1E"+otp;
}

std::string successSignUpAckP1(std::string username){
    return "333\x1F\x1ESignup\x1F\x1E"+username+"\x1F\x1EOtpSended";
}
std::string successSignUpAckFinal(std::string username){
    return "200\x1F\x1ESignup\x1F\x1E"+username;
}
std::string failedSignUpAck(){
    return "300\x1F\x1ESignup\x1F\x1ExxxxNULLxxxx";
}
std::string failedSignUpAckUsernameNA(){
    return "301\x1F\x1ESignup\x1F\x1ExxxxNULLxxxx";
}
std::string failedSignUpAckEmailAU(){
    return "302\x1F\x1ESignup\x1F\x1ExxxxNULLxxxx";
}
std::string failedOtpVerifyAck(){
    return "334\x1F\x1EOtpVerify\x1F\x1ExxxxNULLxxxx";
}

int readSignupAck(char communication[COMMUNICATION_SIZE]){
    std::string message(communication);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));

    if (tokens.empty()) {
        return COMM_ERROR;
    }

    if(tokens[0].compare("200")==0&&tokens[1].compare("Signup")==0){
        return COMM_OK;
    }
    if(tokens[0].compare("300")==0&&tokens[1].compare("Signup")==0){
        return SIGNUP_ERR;
    }
    if(tokens[0].compare("301")==0&&tokens[1].compare("Signup")==0){
        return SIGNUP_ERR_USERNAME_NOT_AVAILABLE;
    }
    if(tokens[0].compare("302")==0&&tokens[1].compare("Signup")==0){
        return SIGNUP_ERR_EMAIL_AU;
    }
    if(tokens[0].compare("333")==0&&tokens[1].compare("Signup")==0&&tokens[3].compare("OtpSended")==0){
        return SIGNUP_OTP_REQUEST;
    }
    if(tokens[0].compare("334")==0&&tokens[1].compare("OtpVerify")==0){
        return OTPVERIFY_FAILED;
    }
    return COMM_ERROR;
}

///***************************************************************

//ADD MESSAGGE

std::string addMsgComm(std::string title,std::string author,std::string body,std::string token){
    return "Add_msg\x1F\x1E"+title+"\x1F\x1E"+author+"\x1F\x1E"+body+"\x1F\x1Etoken\x1F\x1E"+token;
}

std::string successAddMsgAck(std::string username){
    return "200\x1F\x1E"+username+"\x1F\x1E"+"AddMsg";
}
std::string failedAddMsgAck(std::string username){
    return "400\x1F\x1E"+username+"\x1F\x1E"+"AddMsg";
}
std::string failedAddMsgAckTM(std::string username){
    return "401\x1F\x1E"+username+"\x1F\x1E"+"AddMsg";
}

int readAddMsgAck(char communication[COMMUNICATION_SIZE]){
    std::string message(communication);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));
    
     for (const auto& token : tokens) {
        std::cout << token << std::endl;
    } 
    
    if (tokens.empty()) {
        return COMM_ERROR;
    }

    if(tokens[0].compare("200")==0&&tokens[2].compare("AddMsg")==0)
        return COMM_OK;
    if(tokens[0].compare("400")==0&&tokens[2].compare("AddMsg")==0)
        return ADDMESS_ERR;
    if(tokens[0].compare("401")==0&&tokens[2].compare("AddMsg")==0)
        return TOKEN_MISMATCH;

    return COMM_ERROR;
}

///***************************************************************

//RETRIEVE MESSAGE

std::string rtvMsgComm(std::string mid,std::string token){
    return "Rtv_msg\x1F\x1E"+mid+"\x1F\x1Etoken\x1F\x1E"+token;
}

std::string rtvMsgCommCycle(std::string mid,std::string token,int n){
    return "Rtv_msgCycle\x1F\x1E"+mid+"\x1F\x1E"+std::to_string(n)+"\x1F\x1Etoken\x1F\x1E"+token;
}

std::string successRtvMsgAck(std::string username,std::string author,std::string title,std::string body){
    return "200\x1F\x1E"+username+"\x1F\x1ERtvMsg\x1F\x1E"+author+"\x1F\x1E"+title+"\x1F\x1E"+body;
}
std::string failedRtvMsgAck(std::string username){
    return "450\x1F\x1E"+username+"\x1F\x1E"+"RtvMsg";
}
std::string failedRtvNMsgAck(std::string username){
    return "550\x1F\x1E"+username+"\x1F\x1E"+"RtvMsg";
}
std::string failedRtvMsgAckTM(std::string username){
    return "451\x1F\x1E"+username+"\x1F\x1E"+"RtvMsg";
}

int readRtvMsgAck(char buffer[COMM_BUFFER_SIZE],communicationsData *dataOut){
    std::string message(buffer);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));

    if (tokens.empty()) {
        return COMM_ERROR;
    }

    if(tokens[0].compare("200")==0&&tokens[2].compare("RtvMsg")==0){
        dataOut->author=tokens[3];
        dataOut->body=tokens[5];
        dataOut->title=tokens[4];
        return COMM_OK;
    }
    if(tokens[0].compare("450")==0&&tokens[2].compare("RtvMsg")==0)
        return RTVMESS_ERR;
    if(tokens[0].compare("451")==0&&tokens[2].compare("RtvMsg")==0)
        return TOKEN_MISMATCH;
    if(tokens[0].compare("550")==0&&tokens[2].compare("RtvMsgCycle")==0)
        return RTVNMESS_ERR;
    return COMM_ERROR;
}

void identifyCommunicationsType(char communication[COMMUNICATION_SIZE],communicationsData *dataOut){

    std::string message(communication);
    std::string delimiter = "\x1F\x1E";
    std::vector<std::string> tokens;
    std::vector<int>::size_type sz;
    
    size_t last = 0;
    size_t next = 0;
    
    
    while ((next = message.find(delimiter, last)) != std::string::npos) {
        
        tokens.push_back(message.substr(last, next - last));
        
        last = next + delimiter.length();
    }
    
    // Add the final token after the last delimiter
    tokens.push_back(message.substr(last));
    
    /*for (const auto& token : tokens) {
        std::cout << token << std::endl;
    } */
    
    /*if (tokens.empty()) {
        return COMM_ERROR;
    }*/
    
    sz=tokens.size();
    //std::cout<<"size: "<<sz<<std::endl;
    if(sz==3){
        if(tokens[0].compare("Login")==0){
            dataOut->code=LOGIN_COMM;
            dataOut->username=tokens[1];
            dataOut->password=tokens[2];
            return;
        }

        if(tokens[0].compare("Logout")==0){
            dataOut->token=tokens[2];
            dataOut->code=LOGOUT_COMM;
            return;
        }
        if(tokens[0].compare("CloseConn")==0){
            dataOut->token=tokens[2];
            dataOut->code=CLOSE_CONN_COMM;
            return;
        }
        
    }
    if(sz==4){
        if(tokens[0].compare("Signup")==0){
            dataOut->email=tokens[1];
            dataOut->username=tokens[2];
            dataOut->password=tokens[3];
            dataOut->code=SIGNUP_COMM;
            return;
        }
        if(tokens[0].compare("Rtv_msg")==0){
            dataOut->code=RTVMESS_COMM;
            dataOut->mid=atoi(tokens[1].c_str());
            dataOut->token=tokens[3];
            return;
        }
        if(tokens[0].compare("OtpVerify")==0){
            dataOut->email=tokens[1];
            dataOut->username=tokens[2];
            dataOut->otp=tokens[3];
            dataOut->code=OTPVERIFY_COMM;
            return;
        }
        
    }
    if(sz==5){
        if(tokens[0].compare("Rtv_msgCycle")==0){
            dataOut->code=RTVNMESS_COMM;
            dataOut->mid=atoi(tokens[1].c_str());
            dataOut->cycle=atoi(tokens[2].c_str());
            dataOut->token=tokens[4];
            return;
        }
        
    }
    if(sz==6){
        if(tokens[0].compare("Add_msg")==0){
            dataOut->code=ADDMESS_COMM;
            dataOut->author=tokens[1];
            dataOut->title=tokens[2];           
            dataOut->body=tokens[3];
            dataOut->token=tokens[5];
            return;
        }
        
    }
    dataOut->code=COMM_ERROR;
    return;
}
        

#endif

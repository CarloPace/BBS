#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <regex>
#include "user.h"
#include "message.h"
#include "communications.h"
#include "hideCin.h"
#include "cryptoUtils.h"


#define PORT 8443
#define LOOPBACK_ADDR "127.0.0.1"
#define BUFFER_SIZE 2049



void flushStdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

void removeNewLine(char *buffer){
    buffer[strcspn(buffer, "\n")] = 0;
}

int main() {

    bool exitVar=false;
    int retValue=0;
    
    int serverSocket = 0;
    struct sockaddr_in serv_addr;
    ssize_t recvBytes=0;
    
    
    char buffer[BUFFER_SIZE] = {0};
    std::string buffer2;
    char commBuffer[BUFFER_SIZE]={0};
    
    
    char passwdBuffer[PASSWORD_LEN]={0};
    unsigned char hash[256]={0};
    
    std::regex reg("^(?=.*[0-9])(?=.*[!@#$%&*])(?=.*[A-Z])[A-Za-z0-9!@#$%&*]{8,32}$");
    
    EVP_PKEY* clientPubKey=nullptr;
    EVP_PKEY* clientPrvKey=nullptr;
    EVP_PKEY* serverPubKey=nullptr;
    DH* dhParams=nullptr;
    std::vector<unsigned char> aesKey;
    std::vector<unsigned char> nonceKey;
    
    unsigned int serverCommSeqNumber=0;
    unsigned int clientCommSeqNumber=0;
    
    //Loading keys
    clientPrvKey = loadPrivateKey("../keys/client_private.pem");
    if (!clientPrvKey) {
            print_error("Failed to load client private key");
            exit(EXIT_FAILURE);
    }
    print_green("Client private key loaded successfully");
     
    clientPubKey = loadPublicKey("../keys/client_public.pem");
    if (!clientPubKey) {
            print_error("Failed to load client public key");
            exit(EXIT_FAILURE);
    } 
    print_green("Client public key loaded successfully");
     
    serverPubKey = loadPublicKey("../keys/server_public.pem");
    if (!serverPubKey) {
            print_error("Failed to load server public key");
            exit(EXIT_FAILURE);
    } 
    print_green("Server public key loaded successfully");
    
    dhParams=getStandardDHParams();
    if (!dhParams) {
            print_error("Failed to load DH parameters");
            exit(EXIT_FAILURE);
    } 
    print_green("DH parameters loaded");
                   
    
    
    
    //connection established
    
    int t=0;
    int index=0;
    int i2=0;
    int menuDigit=0;
    bool successfullLogin=false;

    User user;
    Message msg;
    communicationsData cData;
    std::string temp;
    std::string temp2;
    
    if(!clientEstablishSecureConnection(LOOPBACK_ADDR,PORT,clientPubKey,clientPrvKey,serverPubKey,dhParams,&serverSocket,aesKey,nonceKey)){
    	print_error("Failed to establish secure connection, exiting");
    	exit(EXIT_FAILURE);
    }
    
    while(!exitVar){
        
        
        t=-1;
        menuDigit=0;
        std::cout<<"Choose operation:\n    [1] Login\n    [2] Sign-up\n    [3] Exit"<<std::endl;
        std::cin>>menuDigit;
        flushStdin();
        if(menuDigit==1){
            //login
            std::cout<<"Type your username : ";
            fgets(buffer,USERNAME_LEN,stdin);
            removeNewLine(buffer);
            user.setUsername(buffer);
            
            std::cout<<"Insert password : ";
            HideStdinKeystrokes();
            fgets(buffer,PASSWORD_LEN,stdin);
            removeNewLine(buffer);
            ShowStdinKeystrokes();
            std::cout<<std::endl;
            hashSHA256(buffer,hash);
            user.setPassword(bytes_to_hex_string(hash,PASSWORD_LEN).c_str());
            
            buffer2=loginCom(user.getUsername(),user.getPassword());
            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
            if(retValue==-1){
            	continue;
            }
            
            recvBytes=receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
            if(recvBytes==0){
                print_green("Connection closed by the server, exiting");
                //close connection
                exitVar=true;
           }
           if(recvBytes==-1){
               print_error("Connection error with the client");
               close(serverSocket);
               exit(EXIT_FAILURE);
           }
            t=readLoginAck(commBuffer,&cData);
            OPENSSL_cleanse(buffer,BUFFER_SIZE);
            OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
            
            if(t==COMM_OK){
                successfullLogin=true;
                user.setToken((char*)cData.token.c_str());
                user.setLmid(cData.mid);
                OPENSSL_cleanse(buffer,BUFFER_SIZE);
            }           
            if(successfullLogin&&!exitVar){
                memset(buffer,BUFFER_SIZE,0);
                print_green("Hello "+user.getUsername());
                while(successfullLogin){
                    std::cout<<"Choose operation:\n    [1] List latest available messages\n    [2] Get message by Id\n"<<
                        "    [3] Add message to BBS\n    [4] Logout\n    [5] Logout & Exit"<<std::endl;
                    std::cin>>menuDigit;
                    flushStdin();
                    switch(menuDigit){
                        case 1:
                            if(user.getLmid()==0){
                                std::cout<< "There are no message available yet, send a messagge and you will be the first user that sent the first messagge in the BBS"<<std::endl;
                                break;
                            }
                            std::cout<<user.getLmid()<<" messages available"<<std::endl;
                            std::cout<<" Type how many messages , you want to read starting from the last message:";
                            std::cin>>index;
                            if(index>user.getLmid()){
                            	print_yellow("Invalid index");
                            	break;
                            }
                            flushStdin();
                            buffer2=rtvMsgCommCycle(std::to_string(user.getLmid()),user.getToken(),index);
                            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                            if(retValue==-1){
            	               print_error("Error occured while communicating with BBS, exiting");
            	               exit(EXIT_FAILURE);
                            }
                            i2=0;
                            while(index>0){
                                recvBytes=receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                                if(recvBytes==0){
                                     print_green("Connection closed by the server");
                                     exitVar=true;
                                     //close connection
                                     break;
                                }
                                if(recvBytes==-1){
                                    print_error("Connection error with the client");
                                    close(serverSocket);
                                    exit(EXIT_FAILURE);
                                }
                                t=readRtvMsgAck(commBuffer,&cData);                               
                                OPENSSL_cleanse(buffer,BUFFER_SIZE);                                
                                OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                                if(t==COMM_OK){
                                    //std::cout<<"Message "<<user.getLmid()-i2<<std::endl;
                                    //std::cout<<"    Author: "<<cData.author<<std::endl<<"    Title: "<<cData.title<<std::endl<<"    Body: "<<cData.body<<std::endl;
                                    std::cout<<"["<<user.getLmid()-i2<<"]"<<"    Title: "<<cData.title<<std::endl;
                                }
                                if(t==RTVNMESS_ERR){
                                    std::cerr<<"Message "<<user.getLmid()-i2<<" retrieve failed, retry"<<std::endl;
                                }
                                //eliminare token mismatch, tutti possono leggere i messaggi
                                if(t==TOKEN_MISMATCH)
                                    std::cerr<< "Token mismatch"<<std::endl;
                                index-=1;
                                i2+=1;
                                }
                            break;
                        case 2:
                            if(user.getLmid()==0){
                                std::cout<< "There are no message yet, send a message or wait until another user send one"<<std::endl;
                                break;
                            }
                            std::cout<< "There are "<<user.getLmid()<<" messages" <<std::endl<<"ID available from 1 to "<<user.getLmid()<<std::endl;
                            std::cout<< "Type the index of the message you want to read: ";
                            std::cin>>index;
                            flushStdin();
                            index-=1;
                            
                            buffer2=rtvMsgComm(std::to_string(index),user.getToken());
                            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                            if(retValue==-1){
            	               print_error("Error occured while communicating with BBS, exiting");
            	               exit(EXIT_FAILURE);
                            }
                            
                            receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                            if(recvBytes==0){
                                 print_green("Connection closed by the server");
                                 exitVar=true;
                                 //close connection
                                 break;
                            }
                            if(recvBytes==-1){
                                print_error("Connection error with the client");
                                close(serverSocket);
                                exit(EXIT_FAILURE);
                            }
                            t=readRtvMsgAck(commBuffer,&cData);
                            OPENSSL_cleanse(buffer,BUFFER_SIZE);
                            OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                            
                            if(t==COMM_OK){
                            	std::cout<< std::endl << "Message " <<cData.mid << std::endl;
                                std::cout<< "    Author: "<<cData.author<<std::endl<<"    Title: "<<cData.title<<std::endl<<"    Body: "<<cData.body<<std::endl<<std::endl;
                            }
                            if(t==RTVMESS_ERR)
                                std::cerr<<"Message retrieve failed, retry"<<std::endl;
                            if(t==TOKEN_MISMATCH)
                                std::cerr<< "Token mismatch"<<std::endl;
                            break;
                        case 3:
                            std::cout<< "Type title of the message: "<<std::endl;
                            fgets(buffer,TITLE_LENGTH,stdin);
                            removeNewLine(buffer);
                            msg.setTitle(buffer);
                            
                            std::cout<< "type body of the message: "<<std::endl;
                            fgets(buffer,BODY_LENGTH,stdin);
                            removeNewLine(buffer);
                            msg.setBody(buffer);
                            msg.setAuthor(user.getUsername().c_str());
                            
                            
                            buffer2=addMsgComm(msg.getAuthor(),msg.getTitle(),msg.getBody(),user.getToken());
                            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                            if(retValue==-1){
            	               print_error("Error occured while communicating with BBS, exiting");
            	               exit(EXIT_FAILURE);
                            }
                            
                            receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                            if(recvBytes==0){
                                 print_yellow("Connection closed by the server");
                                 exitVar=true;
                                 //close connection
                                 break;
                            }
                            if(recvBytes==-1){
                                print_error("Connection error with the client");
                                close(serverSocket);
                                exit(EXIT_FAILURE);
                            }
                            
                            t=readAddMsgAck(commBuffer);
                            OPENSSL_cleanse(buffer,BUFFER_SIZE);
                            OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                            //verify result
                            if(t==COMM_OK){
                                print_green("Message added correctly");
                                user.setLmid(user.getLmid()+1);
                            }
                            if(t==ADDMESS_ERR)
                                print_yellow("Error in adding message");
                            if(t==TOKEN_MISMATCH)
                                std::cout<<"Error in adding message (token mismatch)"<<std::endl;
                            break;
                        case 4:
                            std::cout<< "Executing logout"<<std::endl;
                            
                            buffer2=logoutCom(user.getUsername(),user.getToken());
                            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                            if(retValue==-1){
            	               print_error("Error occured while communicating with BBS, exiting");
            	               exit(EXIT_FAILURE);
                            }
                            
                            recvBytes=receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                            if(recvBytes==0){
                                 print_yellow("Connection closed by the server");
                                 exitVar=true;
                                 //close connection
                                 break;
                            }
                            if(recvBytes==-1){
                                print_error("Connection error with the client");
                                close(serverSocket);
                                exit(EXIT_FAILURE);
                            }
                            t=readLogoutAck(commBuffer);
                            OPENSSL_cleanse(buffer,BUFFER_SIZE);
                            OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                            if(t==COMM_OK){
                                std::cout<<"Logout successfull"<<std::endl;
                                successfullLogin=false;
                                clientRenegotiateKeys(serverSocket,clientPubKey,clientPrvKey,serverPubKey,aesKey,nonceKey);
                            }
                            if(t==LOGOUT_FAILED) 
                                std::cout<<"Logout failed...retry"<<std::endl;                
                            break;
                        case 5:
                            //Closing connection with server
                            std::cout<< "Closing connection with server"<<std::endl;
                            
                            buffer2=closeConnCom(user.getUsername(),user.getToken());
                            retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                            if(retValue==-1){
            	               print_error("Error occured while communicating with BBS, exiting");
            	               exit(EXIT_FAILURE);
                            }
                            successfullLogin=false;
                            exitVar=true;                                                    
                            break;
                        default:
                            std::cout<< "operation not allowed"<<std::endl;
                            break;
                    }
                 }
            }
            if(t==LOGIN_FAILED)
                std::cout<<"Login attempt failed, retry"<<std::endl;
            continue;
        }
        if(menuDigit==2){
            //sign up phase
            std::cout<<"Sign-up phase"<<std::endl;
            
            std::cout<<"Type your email: ";
            fgets(buffer,EMAIL_LEN+1,stdin);
            removeNewLine(buffer);
            user.setEmail(buffer);

            
            std::cout<<"Type your username (Maximum lenght 32 charachters): ";
            fgets(buffer,USERNAME_LEN+1,stdin);
            removeNewLine(buffer);
            user.setUsername(buffer);
            
            OPENSSL_cleanse(buffer,PASSWORD_LEN);
            
            std::cout<<"Insert password (Minimum Lenght 8 ,Maximum lenght 32 characters, at least one special character"<<std::endl;
            std::cout<<"at least one Uppercase character and at least one number: ";
            HideStdinKeystrokes();
            fgets(buffer,PASSWORD_LEN+1,stdin);
            removeNewLine(buffer);;
            
            
            std::cout<<std::endl<<"Re-type your password: ";
            fgets(passwdBuffer,PASSWORD_LEN+1,stdin);
            removeNewLine(passwdBuffer);
            ShowStdinKeystrokes();
            
            std::cout<<std::endl;
            
            if(!std::regex_match(buffer,reg))
                std::cout<<std::endl<<"The password choosen doesn't fullfill all the requirements...retry"<<std::endl;
            else{
                if(memcmp(buffer,passwdBuffer,PASSWORD_LEN)==0){
                
                    hashSHA256(buffer,hash);
                    user.setPassword(bytes_to_hex_string(hash,PASSWORD_LEN).c_str());
                    
                    buffer2=signupCom(user.getEmail(),user.getUsername(),user.getPassword());
                    retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                    if(retValue==-1){
            	         print_error("Error occured while communicating with BBS, exiting");
            	         exit(EXIT_FAILURE);
                    } 
                              
                    recvBytes=receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                    if(recvBytes==0){
                         print_yellow("Connection closed by the server");
                         exitVar=true;
                         //close connection
                         continue;
                    }
                    if(recvBytes==-1){
                         print_error("Connection error with the client");
                         close(serverSocket);
                         exit(EXIT_FAILURE);
                    }
                    t=readSignupAck(commBuffer);
                    OPENSSL_cleanse(buffer,BUFFER_SIZE);
                    OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                    
                    if(t==SIGNUP_OTP_REQUEST){
                        std::cout<<std::endl<<"Otp sended to your email adress, please type the otp to verify your identity:";
                        fgets(buffer,OTP_LEN+1,stdin);
                        removeNewLine(buffer);
                        
                        ShowStdinKeystrokes();
                        std::cout<<std::endl;
                        
                        buffer2=otpVerifyComm(user.getEmail(),user.getUsername(),std::string(buffer));
                        
                        retValue=sendEncryptedMessage(serverSocket,aesKey,nonceKey,clientCommSeqNumber,(const unsigned char*)buffer2.c_str(),buffer2.length());
                        if(retValue==-1){
            	            print_error("Error occured while communicating with BBS, exiting");
            	            exit(EXIT_FAILURE);
                        } 
                                  
                        recvBytes=receiveEncryptedMsg(serverSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,serverCommSeqNumber,(unsigned char*)commBuffer);
                        if(recvBytes==0){
                            print_yellow("Connection closed by the server");
                            exitVar=true;
                            //close connection
                            continue;
                        }
                        if(recvBytes==-1){
                            print_error("Connection error with the client");
                            close(serverSocket);
                            exit(EXIT_FAILURE);
                        }
                        t=readSignupAck(commBuffer);
                        OPENSSL_cleanse(buffer,BUFFER_SIZE);
                        OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
                        
                        
                        if(t==COMM_OK){
                            print_green("Sign-up successfull, now you can login");
                            clientRenegotiateKeys(serverSocket,clientPubKey,clientPrvKey,serverPubKey,aesKey,nonceKey);
                        }
                        if(t==OTPVERIFY_FAILED)
                            print_yellow("Otp verification failed, retry to sign-up");
                        
                        
                    }
                    if(t==SIGNUP_ERR)
                       print_yellow("Sign-up failed , retry to sign-up");
                    if(t==SIGNUP_ERR_USERNAME_NOT_AVAILABLE)
                        print_yellow("Username not available, try another username");
                    if(t==SIGNUP_ERR_EMAIL_AU)
                        print_yellow("Email alredy used");
                }else
                    print_yellow("The passwords inserted doesn't match between each others");
            }
        }
        if(menuDigit==3)
            exitVar=true;
        if(menuDigit<1||menuDigit>3)
            std::cout<< "Operation not supported"<<std::endl;
        //after successfull login
    }
    std::cout<<"Closing BBS client application";
    
    DH_free(dhParams);
    EVP_PKEY_free(serverPubKey);
    EVP_PKEY_free(clientPrvKey);
    EVP_PKEY_free(clientPubKey);
    OPENSSL_cleanse(aesKey.data(),aesKey.size());
    OPENSSL_cleanse(nonceKey.data(),nonceKey.size());   
    close(serverSocket);
    return 0;
}

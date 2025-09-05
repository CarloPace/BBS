#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <hiredis/hiredis.h>
#include <csignal>
#include <thread>
#include <chrono> 
#include "communications.h"
#include "query.h"
#include "cryptoUtils.h"
#include "otpFileIO.h"

#define PORT 8443
#define REDIS_PORT 6379
#define LOOPBACK_ADDR "127.0.0.1"
#define BUFFER_SIZE 2049
#define MAX_QUERY_SIZE 512

void print_hex2(const std::string& label, const char* buffer, size_t size) {
    std::cout << label << " (" << size << " bytes): ";

    // Set cout to format output as hex
    std::cout << std::hex << std::setfill('0');

    for (size_t i = 0; i < size; ++i) {
        // std::setw(2) ensures each byte is printed as two characters (e.g., 0F)
        // We cast the char to an int to ensure it's printed as a number,
        // and then to unsigned char to prevent sign extension for negative values.
        std::cout << std::setw(2) << static_cast<int>(static_cast<unsigned char>(buffer[i])) << " ";
    }

    // Reset cout to its default decimal format
    std::cout << std::dec << std::endl;
}

volatile sig_atomic_t serverShutdown = false;

void signal_handler(int signal) {
    serverShutdown = true;
}

void task(int id,int clientSocket,EVP_PKEY* serverPrvKey,EVP_PKEY* serverPubKey) {
    
    int redisIntReply=0;
    redisReply *reply;
    
    bool clientDisconnected=false;
    bool clientLoggedOut=false;
    bool clientSignedUp=false;
    bool cErr=false;
    

    EVP_PKEY* clientPubKey=nullptr;
    DH* dhParams=nullptr;
    std::vector<unsigned char> aesKey;
    std::vector<unsigned char> nonceKey;
    
    char buffer[BUFFER_SIZE] = {0};
    char commBuffer[BUFFER_SIZE] = {0};
    
    unsigned int serverCommSeqNumber=0;
    unsigned int clientCommSeqNumber=0;
    
    ssize_t recvBytes=0;
    int retValue=0;
    
    int i=0;
    
    communicationsData data;
    std::string temp;
    
    
    
    //Connecting to redis
    redisContext *c = redisConnect(LOOPBACK_ADDR, REDIS_PORT);
    if (c != NULL && c->err) {
        fprintf(stderr,"Error: %sn", c->errstr);
        exit(EXIT_SUCCESS);
    }

    //redisReply *reply;
    reply = (redisReply*)redisCommand(c, "AUTH carlo password");
    print_green("Connected to Redis");
    freeReplyObject(reply);
    
    dhParams=getStandardDHParams();
    if (!dhParams) {
            print_error("Failed to load DH parameters");
            clientDisconnected=true;
    	    cErr=true;
    } 
    print_green("DH parameters loaded");
    if (!generateDHKeypair(dhParams)) {
            print_error("Failed to generate DH key");
            clientDisconnected=true;
    	    cErr=true;
   }
    

    
    if(!serverEstablishSecureConnection(clientSocket,serverPrvKey,serverPubKey,dhParams,clientPubKey,aesKey,nonceKey)){
    	print_error("Failed to establish secure connection with client, closing thread");
    	clientDisconnected=true;
    	cErr=true;
    }

    while(!clientDisconnected){
            
            
            if(clientLoggedOut||clientSignedUp){
            	if(!serverRenegotiateKeys(clientSocket,serverPrvKey,serverPubKey,clientPubKey,aesKey,nonceKey)){
            		print_error("Failed to renegotiate keys with client, closing connection");
    				clientDisconnected=true;
    				cErr=true;
            	}
            	clientLoggedOut=false;
            	clientSignedUp=false;
            }
    
	    	OPENSSL_cleanse(buffer,BUFFER_SIZE);
	        OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
        
        
	        recvBytes=receiveEncryptedMsg(clientSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,clientCommSeqNumber,(unsigned char*)commBuffer);
	        if(recvBytes==0){
	            print_green("Connection closed by the client");
	            //close connection
	            clientDisconnected=true;
	            break;
	        }
	        if(recvBytes==-1){
	            print_error("Connection error with the client");
	            cErr=true;
	            break;
	        }
	        
	        identifyCommunicationsType(commBuffer,&data);
	        OPENSSL_cleanse(buffer,BUFFER_SIZE);
	        OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
        
	        if(data.code==LOGIN_COMM){
            
	            
	            reply = retrievePasswordOfUser(c,data.username);
            
	            if(reply->type!=REDIS_REPLY_NIL&&reply->type==REDIS_REPLY_STRING&&data.password.compare(reply->str)==0){
            
                    std::string clientToken=generateOtp(64);
                    
	            
	                freeReplyObject(reply);
	                
	                reply = retrieveLastMid(c);
	                
	                
	                temp=loginAck(data.username,clientToken,atoi(reply->str));
	                retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length()); 
	                if(retValue==-1){
	                    print_error("Connection error with the client,closing connection...");
	                    cErr=true;
	                    break;
	                }              
	                freeReplyObject(reply);
	                //receiving new request from authenticated user
	                while(!clientLoggedOut){
	                    
	                    recvBytes=receiveEncryptedMsg(clientSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,clientCommSeqNumber,(unsigned char*)commBuffer);
	                    if(recvBytes==0){
	               	        print_yellow("Connection closed by the client");
	                        //close connection
	                        clientLoggedOut=true;
	                        clientDisconnected=true;
	                        break;
	                    }
	                	if(recvBytes==-1){
	                    	print_error("Connection error with the client, closing connection...");
	                    	cErr=true;
	                    	break;
	                	}
	                	identifyCommunicationsType(commBuffer,&data);
	                	OPENSSL_cleanse(buffer,BUFFER_SIZE);
	                	OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
	                
	                	
	                	if(data.code==COMM_ERROR){
	                		print_yellow("Communication received , not identified");
	                	}
	                	if(data.code==LOGOUT_COMM){
	                    	
	                    	if(data.token.compare(clientToken)==0){
	                        	temp=successLogoutAck(data.username);
	                        	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                        	if(retValue==-1){
	                            	print_error("Connection error with the client, closing connection...");
	                    	        cErr=true;
	                    	        break;
	                        	}
	                        	clientLoggedOut=true;
	                    	}else{
	                        	temp=failedLogoutAck(data.username);
	                        	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                        	if(retValue==-1){
	                            	print_error("Connection error with the client, closing connection...");
	                    	        cErr=true;
	                    	        break;
	                        	} 
	                    	}
	                	}
	                	if(data.code==CLOSE_CONN_COMM){
	         
	                    	if(data.token.compare(clientToken)==0){
	                        	
	                        	clientLoggedOut=true;
	                    	    clientDisconnected=true;
	                    	}
	                	}
	                	if(data.code==ADDMESS_COMM){
	                    	if(data.token.compare(clientToken)==0){
	                    	
	                    	    ////////////////////////// THIS SHOULD BE A TRANSACTION
                        
	                        
	                        	reply = retrieveLastMid(c);
	                        	int lm=atoi(reply->str);
	                        	freeReplyObject(reply);
	                        	
	                        	reply = addMessage(c, lm, data.username, data.title, data.body);
	                        	if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
	                            	// Handle the error...
	                            	if (reply) {
	                                	printf("Redis Error: %s\n", reply->str);
	                                	freeReplyObject(reply);
	                                	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	} else {
	                                	printf("Connection Error: %s\n", c->errstr);
	                                	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	}
	                        	}
                        
	                       
	                        	redisIntReply=reply->integer;
	                        	//std::cout<<"r: "<<redisIntReply<<std::endl;
	                        	freeReplyObject(reply);
	                        	reply = incrementMid(c);
	                        	
	                        	///////////////////////////////
	                        	if(reply->integer&&redisIntReply==3){
	                            	freeReplyObject(reply);
	                            	//messagge correctly added
	                            	temp=successAddMsgAck(data.username);
	                            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                            	if(retValue==-1){
	                                	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	}
	                        	}else{
	                            	freeReplyObject(reply);
	                            	temp=failedAddMsgAck(data.username);
	                            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                            	if(retValue==-1){
	                                 	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	}  
	                        	}
	                    	}else{
	                        	temp=failedAddMsgAckTM(data.username);
	                        	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                        	if(retValue==-1){
	                            	print_error("Connection error with the client, closing connection...");
	                    			cErr=true;
	                    			break;
	                        	}
	                   		}
	                	}
	                	if(data.code==RTVMESS_COMM){
	                    	if(data.token.compare(clientToken)==0){
	                        
	                        	reply = retrieveMessageByMid(c,std::to_string(data.mid));
	                        	
	                        	if(reply->elements==6){
	                            
	                            	//messagge correctly retrieved
	                            	temp=successRtvMsgAck(data.username,reply->element[1]->str,reply->element[3]->str,reply->element[5]->str);
	                            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                            	if(retValue==-1){
	                                	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	}
	                            	freeReplyObject(reply);
	                        	}else{
	                            	temp=failedRtvMsgAck(data.username);
	                            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                            	if(retValue==-1){
	                                	print_error("Connection error with the client, closing connection...");
	                    				cErr=true;
	                    				break;
	                            	}
	                            	freeReplyObject(reply);
	                        	}
	                    	}else{                       
	                        	temp=failedRtvMsgAckTM(data.username);
	                        	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                        	if(retValue==-1){
	                             	print_error("Connection error with the client, closing connection...");
	                    			cErr=true;
	                    			break;
	                        	}
	                    	}
	                	}
	                	if(data.code==RTVNMESS_COMM){
	                    	if(data.token.compare(clientToken)==0){
	                        
	                        	int n=0;
	                        	while(n<data.cycle){
	                        
	                            
	                            	reply = retrieveMessageByMid(c,std::to_string(data.mid-n-1));
	                            	if(reply->elements==6){
	                                	temp=successRtvMsgAck(data.username,reply->element[1]->str,reply->element[3]->str,reply->element[5]->str);
	                                	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                                	if(retValue==-1){
		                                     print_error("Connection error with the client, closing connection...");
	                    					 cErr=true;
	                    					break;
	    	                            }
	    	                            freeReplyObject(reply);
	    	                        }else{
	    	                            freeReplyObject(reply);                               
	    	                            temp=failedRtvNMsgAck(data.username);
	    	                            retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	    	                            if(retValue==-1){
	    	                                print_error("Connection error with the client, closing connection...");
	                    					cErr=true;
	                    					break;
	    	                            }
	    	                        }
	    	                        n+=1;
	    	                    }
		
	    	                }else{                      
	    	                    temp=failedRtvMsgAckTM(data.username);
	    	                    retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	    	                    if(retValue==-1){
	    	                         print_error("Connection error with the client, closing connection...");
	                    			 cErr=true;
	                    	         break;
	    	                   }
	    	                }
	    	            }
	    	        }
	    	        if(cErr==true)
	    	        	break;
	    		}else{
	    	    	freeReplyObject(reply);
	    	    	temp=failedLoginAck(data.username);
	    	    	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	    	    	if(retValue==-1){
	    	    	     print_error("Connection error with the client, closing connection...");
	                     cErr=true;
	                     break;
	    	    	}
	    		}
	    	}
	    	          
	    	if(data.code==SIGNUP_COMM){
	    	        
	    	    std::string email=data.email;
	    	    //std::cout<<"Attempted signup"<<std::endl;
	    	    //check email not alredy used
	    	    reply = checkAlredyUsedEmail(c,data.email);
	    	    redisIntReply=reply->integer;
	    	    freeReplyObject(reply);
	    	        
	    	    //check username not alredy used
	    	    reply = checkUsernameAvailable(c,data.username); 
	    	                 
	    	    if(redisIntReply==0&&reply->integer==0){
	    	        
	            	freeReplyObject(reply);
	            	std::string otp=generateOtp(OTP_LEN);
	            	writeOtpOnFile(data.username,otp);
	            	temp=successSignUpAckP1(data.username);
	            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	            	if(retValue==-1){
	                	print_error("Connection error with the client, closing connection...");
	                    cErr=true;
	                    break;
	            	}
                
	            	recvBytes=receiveEncryptedMsg(clientSocket,(unsigned char*)buffer,BUFFER_SIZE,aesKey,nonceKey,clientCommSeqNumber,(unsigned char*)commBuffer);
	            	if(recvBytes==0){
	                	print_yellow("Connection closed by the client");
	                	clientDisconnected=true;
	                	break;
	            	}
	            	if(recvBytes==-1){
	                	print_error("Connection error with the client, closing connection...");
	                    cErr=true;
	                    break;
	            	}
	            	identifyCommunicationsType(commBuffer,&data);
	            	OPENSSL_cleanse(buffer,BUFFER_SIZE);
	            	OPENSSL_cleanse(commBuffer,BUFFER_SIZE);
	                
	                
	            	if(data.code==OTPVERIFY_COMM&&data.otp.compare(otp)==0&&email.compare(data.email)==0){
	                
	                	reply = createUser(c,data.username,data.email,data.password);
	                	redisIntReply=reply->integer;
	                	freeReplyObject(reply);
	                	reply = createEmailKey(c,data.email);
	                	if(strcmp(reply->str,"OK")!=0||redisIntReply!=2){
	                	    temp=failedSignUpAck();
	                	    retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                	    if(retValue==-1){
	                	        print_error("Connection error with the client, closing connection...");
	                    		cErr=true;
	                    		break;
	                	    }
	                	    freeReplyObject(reply);
	                	}else{
	                	    temp=successSignUpAckFinal(data.username);
	                	    retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                	    if(retValue==-1){
	                	        print_error("Connection error with the client, closing connection...");
	                    		cErr=true;
	                    		break;
	                	    }
	                	    clientSignedUp=true;
	                	    freeReplyObject(reply);
	                	}
	            	}else{
	                	temp=failedOtpVerifyAck();
	                	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	                	if(retValue==-1){
	                	    print_error("Connection error with the client, closing connection...");
	                    	cErr=true;
	                    	break;
	                	}
	            	}
	        	}else if(redisIntReply==1){
	            	temp=failedSignUpAckEmailAU();
	            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
	            	if(retValue==-1){
	            	    print_error("Connection error with the client, closing connection...");
	                    cErr=true;
	                    break;
	            	}
	        	}else{
	            	//username alredy exists 
    	        	temp=failedSignUpAckUsernameNA();
	            	retValue=sendEncryptedMessage(clientSocket,aesKey,nonceKey,serverCommSeqNumber,(const unsigned char*)temp.c_str(),temp.length());
            		if(retValue==-1){
            		     print_error("Connection error with the client, closing connection...");
	                     cErr=true;
	                     break;
            		}
        		}
        	}          
    }
    
    EVP_PKEY_free(clientPubKey);
    OPENSSL_cleanse(aesKey.data(),aesKey.size());
    OPENSSL_cleanse(nonceKey.data(),nonceKey.size());
    close(clientSocket);
    redisFree(c);
}

int main() {

    int lastThreadId=0;

    int listeningSocket, clientSocket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
       
    
    EVP_PKEY* serverPrvKey=nullptr;
    EVP_PKEY* serverPubKey=nullptr;
       
    
    std::signal(SIGINT, signal_handler);
     
    //Loading RSA keys
     
    serverPrvKey = loadPrivateKey("../keys/server_private.pem");
    if (!serverPrvKey) {
            print_error("Failed to load server private key");
            exit(EXIT_FAILURE);
    } 
    print_green("Client public key loaded successfully");
     
    serverPubKey = loadPublicKey("../keys/server_public.pem");
    if (!serverPubKey) {
            print_error("Failed to load server public key");
            exit(EXIT_FAILURE);
    } 
    print_green("Server public key loaded successfully");
    

    // Creazione del socket
    if ((listeningSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Binding del socket al port specificato
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        print_error("Set socket options failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(listeningSocket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(listeningSocket);
        exit(EXIT_FAILURE);
    }

    // Listen per connessioni in entrata
    if (listen(listeningSocket, 3) < 0) {
        perror("Listening socket failed");
        close(listeningSocket);
        exit(EXIT_FAILURE);
    }
    
    print_green("Server listening");   
       
    
    
    while(!serverShutdown){
    
        
    
        if ((clientSocket = accept(listeningSocket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            print_error("Accepting connetion failed");
            continue;
        }  
        
        //this should be handled with a finite number of thread (thread pool)
        
        std::thread thread(task, lastThreadId++,clientSocket,serverPrvKey,serverPubKey); 
        thread.detach();
        
            
        
    }
    printf("Shutting down BBS server");
    close(listeningSocket);
    EVP_PKEY_free(serverPrvKey);
    EVP_PKEY_free(serverPubKey);

    return 0;

}

#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <iostream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string>
#include <memory>
#include <cstring>
#include <limits>
#include <vector>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>  
#include <stdexcept> 



#include <openssl/bio.h>

#define MAX_BUFFER_SIZE 2049

#define OTP_LEN 12

#define AES_GCM_KEY_SIZE     32  // 256-bit key
#define AES_GCM_NONCE_SIZE   12  // 96-bit nonce  
#define AES_GCM_TAG_SIZE     16  // 128-bit authentication tag


/**
 * @brief Prints the PUBLIC key part of an EVP_PKEY to stdout in PEM format.
 * @param pkey A pointer to the EVP_PKEY object.
 */
void print_public_key_pem(const EVP_PKEY* pkey) {
    if (!pkey) {
        std::cerr << "Cannot print a null public key." << std::endl;
        return;
    }

    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new(BIO_s_mem()), &BIO_free_all);

    std::cout << "\n--- PUBLIC KEY ---" << std::endl;
    if (!PEM_write_bio_PUBKEY(bio.get(), (EVP_PKEY*)pkey)) {
        std::cerr << "Error writing public key to BIO" << std::endl;
        return;
    }
    
    char* buffer;
    long len = BIO_get_mem_data(bio.get(), &buffer);
    if (len > 0) {
        std::cout.write(buffer, len);
    }
}

/**
 * @brief Prints the PRIVATE key part of an EVP_PKEY to stdout in PEM format.
 * @param pkey A pointer to the EVP_PKEY object.
 */
void print_private_key_pem(const EVP_PKEY* pkey) {
    if (!pkey) {
        std::cerr << "Cannot print a null private key." << std::endl;
        return;
    }

    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    
    std::cout << "\n--- PRIVATE KEY ---" << std::endl;
    if (!PEM_write_bio_PrivateKey(bio.get(), (EVP_PKEY*)pkey, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key to BIO" << std::endl;
        return;
    }

    char* buffer;
    long len = BIO_get_mem_data(bio.get(), &buffer);
    if (len > 0) {
        std::cout.write(buffer, len);
    }
}

int hashSHA256(char * dataIn,unsigned char* dataOut){
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx == nullptr) {
        std::cerr << "Error creating EVP_MD_CTX context" << std::endl;
        return 1;
    }

    // Context initialization
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error initializing the context" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    if(EVP_DigestUpdate(ctx, dataIn, strlen(dataIn)) != 1) {
        std::cerr << "Error in making the hash" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    if(EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        std::cerr << "Error in finishing the hash" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }
    memcpy(dataOut,hash,hash_len);
 
    EVP_MD_CTX_free(ctx);
    return 0;
}


std::string generateOtp(int len) {

    std::stringstream ss;
    unsigned char byte;
    
    if (RAND_poll() != 1){
        std::cerr << "RAND_poll failed, insufficient entropy or error occurred." << std::endl;
        return std::string();
    }

    for (int i = 0; i < len; ++i) {
        // 1. Generate one secure random byte (value 0-255).
        if (RAND_bytes(&byte, 1) != 1) {
            throw std::runtime_error("Failed to generate random byte.");
        }

        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str().substr(0, len);
}

std::string generateToken(){
    unsigned char buf[4]; // 4 bytes = 32 bits
    int random_value;
    char buff2[32]={0};
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char hash2[MD5_DIGEST_LENGTH];
    unsigned int hash_len=0;
    std::string h1;
    std::string h2;
    std::string token;
    std::stringstream ss;
    char tk[31]={0};
    MD5_CTX md5_ctx;
    SHA_CTX sha1_ctx;

    if (RAND_poll() != 1)
        std::cerr << "RAND_poll failed, insufficient entropy or error occurred." << std::endl;
      // Generate cryptographically secure random bytes
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error("Error generating random bytes");
    }
    // Convert bytes to an integer
    random_value = *(int*)buf; 
    sprintf(buff2,"%d",random_value);
    // Context initialization
    MD5_Init(&md5_ctx);

    // Update the context with data
    MD5_Update(&md5_ctx, buff2, strlen(buff2));

    // Finalize the hash and retrieve the result
    MD5_Final(hash2, &md5_ctx);

    
    ss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    h1=ss.str();
    //
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error("Error generating random bytes");
    }
    // Convert bytes to an integer
    random_value = *(int*)buf;
    sprintf(buff2,"%d",random_value);
    SHA1_Init(&sha1_ctx);

    // Update the context with data
    SHA1_Update(&sha1_ctx, buff2, strlen(buff2));

    // Finalize the hash and retrieve the result
    SHA1_Final(hash, &sha1_ctx);

    ss.str("");    // Clear the string content
    ss.clear();
    ss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    h2=ss.str();
    if (RAND_poll() != 1)
        std::cerr << "RAND_poll failed, insufficient entropy or error occurred." << std::endl;
      // Generate cryptographically secure random bytes
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error("Error generating random bytes");
    }
    // Convert bytes to an integer
    random_value = *(int*)buf;

    // Ensure random_value is positive (to avoid negative modulo results)
    random_value = random_value & std::numeric_limits<int>::max();

    // Map the integer to the desired range [min, max]
    random_value = 7 + (random_value % (33 -7 + 1));

    memcpy(tk,h1.substr(1,16).c_str(),15);
    memcpy(tk+15,h2.substr(random_value-7,random_value+7).c_str(),15);
    token=tk;
    std::cout<<"token: "<<token<<std::endl;
}




std::vector<unsigned char> generateCommunicationNonce(int input_value, const std::vector<unsigned char>& key) {
    // 1. Convert integer to bytes (big-endian format)
    unsigned char input_bytes[4];
    input_bytes[0] = (input_value >> 24) & 0xFF;
    input_bytes[1] = (input_value >> 16) & 0xFF;
    input_bytes[2] = (input_value >> 8) & 0xFF;
    input_bytes[3] = input_value & 0xFF;
    
    // 2. Compute HMAC-SHA256 to generate a 32-byte secure hash
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    
    unsigned char* result = HMAC(
        EVP_sha256(),             // Hash function
        key.data(),       // Key (shared secret)
        key.size(),       // Key length
        input_bytes,              // Data to authenticate
        sizeof(input_bytes),      // Data length
        hmac_result,              // Output buffer
        &hmac_len                 // Output length
    );
    
    // Error handling
    if (result == nullptr) {
        throw std::runtime_error("HMAC computation failed");
    }
    // Ensure we have at least 12 bytes to return
    if (hmac_len < 12) {
        throw std::runtime_error("HMAC result is too short for 12-byte extraction");
    }
    
    // 3. Return the first 12 bytes of the HMAC result.
    return std::vector<unsigned char>(hmac_result, hmac_result + 12);
}

void print_error(const std::string& message) {
    const std::string red = "\033[31m";
    const std::string reset = "\033[0m";
    std::cerr << red << message << reset << std::endl;
}

void print_yellow(const std::string& message) {
    const std::string yellow = "\033[33m";
    const std::string reset = "\033[0m";
    std::cout << yellow << message << reset << std::endl;
}

void print_green(const std::string& message) {
    const std::string red = "\033[32m";
    const std::string reset = "\033[0m";
    std::cout << red << message << reset << std::endl;
}

void printHex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl; // Reset to decimal output
}

std::string bytes_to_hex_string(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }

    return ss.str();
}

std::vector<unsigned char> hex_string_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hexadecimal string must have an even number of characters.");
    }
    
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        
        // Convert each hex digit
        auto hex_to_int = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            throw std::invalid_argument("Invalid hex character");
        };
        
        try {
            int high_val = hex_to_int(high);
            int low_val = hex_to_int(low);
            bytes.push_back(static_cast<unsigned char>((high_val << 4) | low_val));
        } catch (const std::exception& e) {
            throw std::invalid_argument("Invalid hex string at position " + std::to_string(i));
        }
    }
    return bytes;
}



void processHandshakeInitMessage(unsigned char *message, unsigned char *key, size_t key_size) {

    char *token;
   

    // Get the first token
    token = strtok(reinterpret_cast<char*>(message), ":#:"); // strtok modifies the input string
    
    

    // Get the second token
    token = strtok(NULL, ":#:");
    
    
    // 1. Check if the token was found
    if (token != NULL) {
        // 2. Get the actual length of the token
        size_t token_len = strlen(token);

        // 3. Determine how much to copy: the smaller of the token length or the buffer size
        size_t copy_len = (token_len < key_size - 1) ? token_len : (key_size - 1);

        // 4. Safely copy the memory and null-terminate
        memcpy(key, token, copy_len);
        key[copy_len] = '\0'; // Ensure null-termination

    } else {
        // Handle the error: second token not found
        print_error("Error: Handshake key token not found.\n");
        key[0] = '\0'; // Set key to empty as a safe default
    }
}

void processHandshakeMessage(std::string message,std::string *key,std::string *signature){

   const std::string delimiter = ":#:";
	
   size_t pos1 = message.find(delimiter);
   if (pos1 == std::string::npos) {
       throw std::runtime_error("Invalid message format: missing first delimiter.");
   }

   // Find the second delimiter
   size_t pos2 = message.find(delimiter, pos1 + delimiter.length());
   if (pos2 == std::string::npos) {
        throw std::runtime_error("Invalid message format: missing second delimiter.");
   }

   // Extract the DH public key (part between the two delimiters)
   size_t key_start = pos1 + delimiter.length();
   *key = message.substr(key_start, pos2 - key_start);

   // Extract the signature (part after the second delimiter)
   size_t sig_start = pos2 + delimiter.length();
   *signature = message.substr(sig_start);

   if (key->empty() || signature->empty()) {
       throw std::runtime_error("Parsing resulted in empty key or signature.");
   }
   
}

EVP_PKEY* receiveClientRsaPubKey(int clientSocket,unsigned char *buffer,size_t BUFFER_SIZE){

	ssize_t readLen = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
	if (readLen <= 0) {
    		std::cerr << "Failed to receive handshake message" << std::endl;
    		return nullptr;
	}

        
	buffer[readLen] = '\0';  // Null terminate for string processing

	unsigned char ckey[1024];  // Adjust size as needed
	memset(ckey, 0, sizeof(ckey));
	

	processHandshakeInitMessage(buffer, ckey,sizeof(ckey));

	std::cout << "RECEIVED CLIENT RSA PUBLIC KEY:" << std::endl;
	// Print as string since it's PEM format
	std::cout << (char*)ckey << std::endl;

	// Create BIO from PEM data instead of using d2i_PUBKEY
	BIO* bio = BIO_new_mem_buf(ckey, -1);
	if (!bio) {
    	   std::cerr << "Failed to create BIO" << std::endl;
    	   return nullptr;
	}

	EVP_PKEY* clientPubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!clientPubKey) {
    	   std::cerr << "Error loading public key from PEM." << std::endl;
    	   return nullptr;
	}

	std::cout << "CLIENT RSA PUBLIC KEY CORRECTLY RECEIVED" << std::endl;
	
	return clientPubKey;
}

int sendRsaPublicKey(int socket,EVP_PKEY *key){

	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
            print_error("Failed to create BIO");
            return -1;
        }
        
        if (PEM_write_bio_PUBKEY(bio, key)==0) {
          print_error("Failed to write public key to BIO");
          BIO_free(bio);
          return -1;
        }
        
        char* pubKeyData;
        long pubKeyLen = BIO_get_mem_data(bio, &pubKeyData);
        if(pubKeyLen<=0){
             print_error("Failed to get BIO data");
             BIO_free(bio);
             return -1;
        }

	std::cout << "CLIENT RSA PUBLIC KEY (2048-bit) TO SEND:" << std::endl;
	std::cout.write(pubKeyData, pubKeyLen);  // Print exact PEM data
        
        
        std::string hmessage = "HANDSHAKE_INIT:#:";
	hmessage.append(pubKeyData, pubKeyLen);
	if(send(socket, hmessage.c_str(), hmessage.length(), 0)<=0){
	    print_error("Failed to send Rsa key");
            BIO_free(bio);
            return -1;
	}
        BIO_free(bio);
        return 1;
}

// Load RSA private key from file
     EVP_PKEY* loadPrivateKey(const std::string& filename, const std::string& password = "") {
        FILE* fp = fopen(filename.c_str(), "r");
        if (!fp) {
            std::cerr << "Failed to open private key file: " << filename << std::endl;
            return nullptr;
        }
        
        EVP_PKEY* pkey = nullptr;
        if (password.empty()) {
            pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        } else {
            pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, (void*)password.c_str());
        }
        
        fclose(fp);
        
        if (!pkey) {
            std::cerr << "Failed to load private key from: " << filename << std::endl;
            ERR_print_errors_fp(stderr);
        }
        
        return pkey;
    }
    
    // Load RSA public key from file
     EVP_PKEY* loadPublicKey(const std::string& filename) {
        FILE* fp = fopen(filename.c_str(), "r");
        if (!fp) {
            std::cerr << "Failed to open public key file: " << filename << std::endl;
            return nullptr;
        }
        
        EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        
        if (!pkey) {
            std::cerr << "Failed to load public key from: " << filename << std::endl;
            ERR_print_errors_fp(stderr);
        }
        
        return pkey;
    }
    
    // Generate RSA key pair and save to files (utility function)
     bool generateAndSaveRSAKeyPair(const std::string& privKeyFile, const std::string& pubKeyFile, int keySize = 2048) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        EVP_PKEY_CTX_free(ctx);
        
        // Save private key
        FILE* privFp = fopen(privKeyFile.c_str(), "w");
        if (!privFp) {
            EVP_PKEY_free(pkey);
            return false;
        }
        
        if (PEM_write_PrivateKey(privFp, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            fclose(privFp);
            EVP_PKEY_free(pkey);
            return false;
        }
        fclose(privFp);
        
        // Save public key
        FILE* pubFp = fopen(pubKeyFile.c_str(), "w");
        if (!pubFp) {
            EVP_PKEY_free(pkey);
            return false;
        }
        
        if (PEM_write_PUBKEY(pubFp, pkey) != 1) {
            fclose(pubFp);
            EVP_PKEY_free(pkey);
            return false;
        }
        fclose(pubFp);
        
        EVP_PKEY_free(pkey);
        std::cout << "RSA key pair generated and saved:" << std::endl;
        std::cout << "Private key: " << privKeyFile << std::endl;
        std::cout << "Public key: " << pubKeyFile << std::endl;
        return true;
    }
    
    
    // signatures function
     void sign_message(const char* message, EVP_PKEY* prvKey, 
                 unsigned char** signature, size_t* sig_len) {
    
    
    	EVP_MD_CTX* ctx = NULL;
    	EVP_PKEY_CTX* pctx = NULL;
    
    
    	// Create signing context
    	ctx = EVP_MD_CTX_new();
    	if (!ctx){
    	    std::cout<<"Error occured creating signing context"<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return;
    	};
    
    	// Initialize for signing with SHA-256
    	if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, prvKey) != 1) {
    	    std::cout<<"Error occured during initialization signing context"<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return;
        };
        
        //Change padding scheme to RSA PSS
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) {
            std::cout << "Error occurred setting PSS padding" << std::endl;
            EVP_MD_CTX_free(ctx);
        	return;
        }
        
        //Set length of Padding to match the length of the message
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) != 1) {
            std::cout << "Error occurred setting PSS salt length" << std::endl;
            EVP_MD_CTX_free(ctx);
            return;
        }
    
        // Add message data
        if (EVP_DigestSignUpdate(ctx, message, strlen(message)) != 1){
           std::cout<<"Error occured during signing "<<std::endl;
           EVP_MD_CTX_free(ctx);
    	    return;
        };
    
    	// Get signature length
    	if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1){
    	    std::cout<<"Error occured during finalization signing "<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return;
        };
    
    	// Allocate signature buffer
    	*signature = (unsigned char*)malloc(*sig_len);
    	if (!*signature) {
    	    std::cout<<"Error occured during buffer allocation "<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return;
        };
    
        // Create signature
        if (EVP_DigestSignFinal(ctx, *signature, sig_len) != 1){
    	    std::cout<<"Error occured during finalization signing "<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return;
        };
        
        EVP_MD_CTX_free(ctx);
    	return;
    
    }
    
     int verify_signature(const char* message,size_t messageLen, EVP_PKEY* pubKey,
                     unsigned char* signature, size_t sigLen) {
    
    	EVP_MD_CTX* ctx = NULL;
    	EVP_PKEY_CTX* pctx = NULL;
    	
    	int res=0;
    
    
    	// Create verification context
    	ctx = EVP_MD_CTX_new();
    	if (!ctx){
    	    std::cout<<"Error occured creating signing context"<<std::endl;
    	    return -1;
    	};
    
    	// Initialize for verification with SHA-256
    	if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pubKey) != 1) {
    	    std::cout<<"Error occured during initialization signing context"<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return -1;
        };
        
        // Set padding scheme
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) {
        	std::cout << "Error occurred setting PSS padding for verification" << std::endl;
        	EVP_MD_CTX_free(ctx);
        	return -1;
    	}
    	
    	// Set padding length
    	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) != 1) {
        	std::cout << "Error occurred setting PSS salt length for verification" << std::endl;
        	EVP_MD_CTX_free(ctx);
        	return -1;
    	}
    
    	// Add message data
    	if (EVP_DigestVerifyUpdate(ctx, message, messageLen) != 1){
    	    std::cout<<"Error occured during verification signature"<<std::endl;
    	    EVP_MD_CTX_free(ctx);
    	    return -1;
        };
    
    	// Verify signature
    	res=EVP_DigestVerifyFinal(ctx, signature, sigLen);
    	    
    
    	EVP_MD_CTX_free(ctx);
        return res;
    }
    
    //dh key sending
     int sendSignedDHPublicKey(int clientSocket,const BIGNUM* DHPub,EVP_PKEY* PrivKey){
    
        
        char* DHPubHex = BN_bn2hex(DHPub);
        if (!DHPubHex) {
            std::cerr << "Failed to convert DH public key to hex" << std::endl;
            return -1;
        }
        
        size_t DHPubLen = strlen(DHPubHex);
        
        std::cout<<"DH PUBLIC KEY (HEX) (LEN : "<<DHPubLen<<") : "<<DHPubHex<<std::endl;
        
        unsigned char* newSignature = nullptr;
		size_t nsignLen = 0;
        
        sign_message(DHPubHex, PrivKey,&newSignature,&nsignLen);
        
        std::string hexSignature;
        
        hexSignature=bytes_to_hex_string(newSignature,nsignLen);
        
        std::cout <<"SIGNATURE (HEX) (LEN :" << hexSignature.length()<<") : "<<hexSignature <<std::endl;
        
        const char* prefix = "HANDSHAKE_1:#:";
		const char* separator = ":#:";
		size_t prefixLen = strlen(prefix);
		size_t separatorLen = strlen(separator);
	
		size_t totalMessageLen = prefixLen + DHPubLen + separatorLen + hexSignature.length();
		char* message = (char*)malloc(totalMessageLen);
	
		if (!message) {
    	    std::cerr << "Failed to allocate message buffer" << std::endl;
            OPENSSL_free(DHPubHex);
            free(newSignature);
            return -1;
       	}
       
       // Build message: "HANDSHAKE_1:#:" + DH_KEY + ":#:" + SIGNATURE
		size_t offset = 0;
		memcpy(message + offset, prefix, prefixLen);
		offset += prefixLen;

		memcpy(message + offset, DHPubHex, DHPubLen);
		offset += DHPubLen;

		memcpy(message + offset, separator, separatorLen);
		offset += separatorLen;
        
        memcpy(message + offset, hexSignature.c_str(), hexSignature.length());
		offset += hexSignature.length();
        
        
        // Send the message
		ssize_t sent = send(clientSocket, message, totalMessageLen, 0);
		if (sent == -1) {
    	    std::cerr << "Failed to send DH handshake message" << std::endl;
    	    return -1;
		}/* else {
    	    std::cout << "DH HANDSHAKE MESSAGE SENT: " << sent << " bytes" << std::endl;
		}*/

		// Clean up memory
		free(message);
		OPENSSL_free(DHPubHex);  // Use OPENSSL_free for BN_bn2hex result
		free(newSignature);
		return 1;

    }
    
     BIGNUM* receiveSignedDHPublicKey(int socket,unsigned char *buffer,size_t BUFFER_SIZE,EVP_PKEY* PubKey){
    
    	BIGNUM *DHPub=nullptr;
    
        size_t bytes_received=recv(socket, buffer, BUFFER_SIZE-1, 0);
        
        buffer[bytes_received] = '\0';
        
        std::string clientDHPubHex(reinterpret_cast<const char*>(buffer), bytes_received);
        
        
        std::string dh_pub_key_hex;
    	std::string signature_hex;
        
        processHandshakeMessage(clientDHPubHex.data(),&dh_pub_key_hex,&signature_hex);
        
        std::cout<<"DH PUBKEY RECEIVED (HEX) (LEN : "<<dh_pub_key_hex.length()<<") : "<<dh_pub_key_hex<<std::endl;
        std::cout<<"SIGNATURE RECEIVED (HEX) (LEN : "<<signature_hex.length()<<") : "<<signature_hex<<std::endl;
        
        //converting the signature from hex to binary
        std::vector<unsigned char> binSignature = hex_string_to_bytes(signature_hex);
        
        if(verify_signature((const char*)dh_pub_key_hex.c_str(),dh_pub_key_hex.length(), PubKey,binSignature.data(),binSignature.size())!=1){
            std::cerr<<"Error validating client signature, handshake failed"<<std::endl;
            return nullptr;
        }
        
        //validating signature
        
        std::cout << "DH PUBKEY CORRECTLY RECEIVED, AUTHENTICATED AND NOT TAMPERED" << std::endl;
        
        
        BN_hex2bn(&DHPub, (const char*)dh_pub_key_hex.c_str());
        
        return DHPub;
    }
    
    //nonces 
    
     int generate_aes_gcm_nonce(unsigned char *nonce) {
    	return RAND_bytes(nonce, AES_GCM_NONCE_SIZE);
    }
	
    // Generate DH parameters
    
     DH* getStandardDHParams() {
    	return DH_get_2048_256();  // RFC 5114
    }


     DH* generateDHParams(int primeLen = 2048) {
        DH* dh = DH_new();
        if (!dh) return nullptr;
        
        if (DH_generate_parameters_ex(dh, primeLen, DH_GENERATOR_2, nullptr) != 1) {
            DH_free(dh);
            return nullptr;
        }
        
        return dh;
    }
    
    // Generate DH key pair
     bool generateDHKeypair(DH* dh) {
        return DH_generate_key(dh) == 1;
    }
    
    // Compute DH shared secret
     std::vector<unsigned char> computeDHSharedSecret(DH* dh, const BIGNUM* peerPubkey) {
    
        int secretLen = DH_size(dh);
        
        std::vector<unsigned char> secret(secretLen);
        
        int len = DH_compute_key(secret.data(), peerPubkey, dh);
        if (len < 0) {
        	print_error("Error occured computing dh key");
        	return{};
        }
        
        secret.resize(len);
        return secret;
    }
    
    // Derive AES key from shared secret using SHA256
    
     std::vector<unsigned char> deriveAESKeyV2(const std::vector<unsigned char>& sharedSecret) {
         // 1. Create a buffer for the hash output.
         // AES-256 requires a 32-byte key. SHA-256 produces a 32-byte hash.
         std::vector<unsigned char> key(32);
         unsigned int key_len;

         // 2. Get the SHA-256 message digest algorithm implementation.
         const EVP_MD* md = EVP_sha256();
         if (md == nullptr) {
              print_error("EVP_sha256() failed.");
         }

         // 3. Create a context for the digest operation.
         EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
         if (mdctx == nullptr) {
             print_error("EVP_MD_CTX_new() failed.");
         }

         // 4. Perform the hash in one go with the "one-shot" EVP_Digest function.
         if (1 != EVP_Digest(
             sharedSecret.data(), // Input data
             sharedSecret.size(),   // Input data length
             key.data(),          // Output buffer
             &key_len,            // Output buffer length
             md,                  // Digest algorithm
             nullptr              // Engine (not needed)
         )) {
           EVP_MD_CTX_free(mdctx); // Clean up on failure
           print_error("EVP_Digest() failed.");
         }
    
         // 5. Clean up the context.
         EVP_MD_CTX_free(mdctx);

         // Optional: Ensure the hash length is what we expect.
         if (key_len != 32) {
             print_error("Derived key is not 256 bits.");
         }

         return key;
     }
    
    std::vector<unsigned char> hkdf_derive(
       const std::vector<unsigned char>& ikm,
       const std::vector<unsigned char>& salt,
       const std::vector<unsigned char>& info,
       size_t out_len) {
       
       /*// 2. A salt (can be public, but should be random)
    std::vector<unsigned char> salt = {'s', 'a', 'l', 't', 'o', 'm', '_', 's', 'a', 'l', 't'};

    try {
        // 3. Derive a 32-byte (256-bit) key for AES encryption
        std::vector<unsigned char> encryption_info = {'a', 'e', 's', '-', 'k', 'e', 'y'};
        std::vector<unsigned char> encryption_key = hkdf_derive(master_secret, salt, encryption_info, 32);

        // 4. Derive a 32-byte (256-bit) key for HMAC authentication
        std::vector<unsigned char> auth_info = {'n', 'o', 'n', 'c','e' ,'-', 'k', 'e', 'y'};
        std::vector<unsigned char> auth_key = hkdf_derive(master_secret, salt, auth_info, 32);*/

        std::vector<unsigned char> derived_key(out_len);
        
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx) {
           print_error("Failed to create EVP_PKEY_CTX.");
        }

        if (EVP_PKEY_derive_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("Failed to initialize HKDF derivation.");
        }

        // Set the hash algorithm
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("Failed to set HKDF hash.");
        }

        // Set the Initial Keying Material (master secret)
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("Failed to set HKDF key.");
        }

        // Set the optional salt
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("Failed to set HKDF salt.");
        }

        // Set the context-specific info
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("Failed to add HKDF info.");
        }

        // Perform the derivation
        size_t derived_key_len = derived_key.size();
        if (EVP_PKEY_derive(pctx, derived_key.data(), &derived_key_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            print_error("HKDF derivation failed.");
        }

        EVP_PKEY_CTX_free(pctx);
        derived_key.resize(derived_key_len); // Adjust size in case it differs

        return derived_key;
    }
    
    
    //AES-GCM
    /* AES-GCM Authenticated Encryption
    * 
    * @param plaintext: Input data to encrypt
    * @param plaintext_len: Length of plaintext
    * @param aad: Additional Authenticated Data (can be NULL)
    * @param aad_len: Length of AAD (0 if aad is NULL)
    * @param key: 256-bit encryption key
    * @param nonce: 96-bit nonce (must be unique for each encryption with same key)
    * @param ciphertext: Output buffer for encrypted data (same size as plaintext)
    * @param tag: Output buffer for authentication tag (16 bytes)
    * 
    * @return: Length of ciphertext on success, -1 on failure
    */
     int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                          const unsigned char *aad, int aad_len,
                          const unsigned char *key,
                          const unsigned char *nonce,
                          unsigned char *ciphertext,
                          unsigned char *tag) {
                       
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    int ret = -1;

    // Validate input parameters
    if (!plaintext || !key || !nonce || !ciphertext || !tag) {
        std::cerr << "Error: Invalid parameters" << std::endl;
        return -1;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create context" << std::endl;
        return -1;
    }

    // Initialize the encryption operation with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Error: Failed to initialize encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set nonce length (96 bits is default for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_SIZE, NULL) != 1) {
        std::cerr << "Error: Failed setting nonce length" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and nonce
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        std::cerr << "Error: Failed to set key and nonce" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide Additional Authenticated Data (AAD) if present
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            std::cerr << "Error: Failed to add AAD" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        std::cerr << "Error: Failed to encrypt message" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        std::cerr << "Error: Failed to finalize encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Get the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "Error: Failed to get authentication tag" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = ciphertext_len; // Success

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
    
    
    int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                          const unsigned char *aad, int aad_len,
                          const unsigned char *tag,
                          const unsigned char *key,
                          const unsigned char *nonce,
                          unsigned char *plaintext) {
                    
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret = -1;

    // Validate input parameters
    if (!ciphertext || !tag || !key || !nonce || !plaintext) {
        std::cerr << "Error: Invalid input parameters" << std::endl;
        return -1;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create context" << std::endl;
        return -1;
    }

    // Initialize the decryption operation with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Error: Failed to initialize decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set nonce length (96 bits is default for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_SIZE, NULL) != 1) {
        std::cerr << "Error: Failed to set nonce length" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and nonce
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        std::cerr << "Error: Failed to set key and nonce" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide Additional Authenticated Data (AAD) if present
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            std::cerr << "Error: Failed to add AAD" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        std::cerr << "Error: Failed to decrypt message" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Set the authentication tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void*)tag) != 1) {
        std::cerr << "Error: Failed to set authentication tag" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption and verify authentication tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) > 0) {
        plaintext_len += len;
        ret = plaintext_len; // Success - authentication passed
    } else {
        std::cerr << "Error: Authentication verification failed" << std::endl;
        // Clear potentially compromised plaintext
        memset(plaintext, 0, plaintext_len);
        ret = -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ret;
    }

     int receiveChallengeMsg(int socket,unsigned char *buffer,size_t BUFFER_SIZE,std::vector<unsigned char> aesKey,std::vector<unsigned char> *challenge){
    	       
        std::vector<unsigned char> cipherText(AES_GCM_NONCE_SIZE);
        std::vector<unsigned char> iv(AES_GCM_NONCE_SIZE);
        std::vector<unsigned char> tag(AES_GCM_TAG_SIZE);
        
        std::string cipherTextHex;
        std::string ivHex;
        std::string challengeHex;
        std::string tagHex;
        
        OPENSSL_cleanse(buffer, BUFFER_SIZE);
        
        
        size_t bytes_received=recv(socket, buffer, BUFFER_SIZE-1, 0);
        
        buffer[bytes_received] = '\0';
        
        
        memcpy(tag.data(),buffer,AES_GCM_TAG_SIZE);
        memcpy(iv.data(),buffer+AES_GCM_TAG_SIZE,AES_GCM_NONCE_SIZE);
        memcpy(cipherText.data(),buffer+AES_GCM_TAG_SIZE+AES_GCM_NONCE_SIZE,AES_GCM_NONCE_SIZE);
            
        
        if(aes_gcm_decrypt(cipherText.data(),cipherText.size(),iv.data(),0,tag.data(),aesKey.data(),iv.data(),challenge->data())==-1){
            std::cerr<<"Error: decrypting message, handshake failed"<<std::endl;
            return -1;
        }
        
        cipherTextHex= bytes_to_hex_string(cipherText.data(), AES_GCM_NONCE_SIZE);
        std::cout << "CYPHERTEXT (HEX) REC.: " << cipherTextHex<<std::endl;
        ivHex= bytes_to_hex_string(iv.data(), AES_GCM_NONCE_SIZE);
        std::cout << "IV (HEX) REC.: " << ivHex <<std::endl;
        tagHex= bytes_to_hex_string(tag.data(), AES_GCM_TAG_SIZE);
        std::cout << "TAG (HEX) REC.: " << tagHex <<std::endl;
        
        challengeHex = bytes_to_hex_string(challenge->data(), AES_GCM_NONCE_SIZE);
        std::cout << "CHALLENGE REC.: " << challengeHex<<std::endl;
        return 1;
	
    }
    
     int sendChallengeMsg(int socket,std::vector<unsigned char> aesKey,std::vector<unsigned char> *challenge){
    	
    	std::vector<unsigned char> cipherText(AES_GCM_NONCE_SIZE);
        std::vector<unsigned char> iv(AES_GCM_NONCE_SIZE);
        std::vector<unsigned char> tag(AES_GCM_TAG_SIZE);
        
        std::string cipherTextHex;
        std::string ivHex;
        std::string challengeHex;
        std::string tagHex;
        
        if(challenge->empty()){
        	challenge->resize(AES_GCM_NONCE_SIZE);
        	generate_aes_gcm_nonce(challenge->data());
        	std::cout<<"GENERATED NONCE : "<<challenge->data()<<std::endl;
        }
        
        generate_aes_gcm_nonce(iv.data());
        
         
        
        size_t cipherLen=aes_gcm_encrypt(challenge->data(), AES_GCM_NONCE_SIZE, iv.data(), 0, aesKey.data(),iv.data(),cipherText.data(),tag.data());
        
        
        // Convert to hex
		ivHex = bytes_to_hex_string(iv.data(), AES_GCM_NONCE_SIZE);
	
		cipherTextHex = bytes_to_hex_string(cipherText.data(), cipherLen);
	
		tagHex = bytes_to_hex_string(tag.data(), AES_GCM_TAG_SIZE);
	
		challengeHex = bytes_to_hex_string(challenge->data(), AES_GCM_NONCE_SIZE);
	
	
		size_t totalMessageLen = AES_GCM_TAG_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_NONCE_SIZE;
		char *message = (char*)malloc(totalMessageLen + 1); // +1 for safety
        
        
        // Build message with correct lengths
		int offset = 0;
		memcpy(message + offset, tag.data(), AES_GCM_TAG_SIZE);
	
		offset += AES_GCM_TAG_SIZE;

		memcpy(message + offset, iv.data(), AES_GCM_NONCE_SIZE);
		offset += AES_GCM_NONCE_SIZE;

		memcpy(message + offset, cipherText.data(), AES_GCM_NONCE_SIZE);
		offset += AES_GCM_NONCE_SIZE;

		if(send(socket, message, offset, 0)<=0){
	   		print_error("Error sending challenge message over socket");
	   		return -1;
		}
        
        
        
        std::cout << "CYPHERTEXT (HEX) (LEN: "<< cipherLen<<") : " << cipherTextHex<<std::endl;
        std::cout<<"IV (HEX) (LEN: "<<ivHex.length()<<") : "<<ivHex<<std::endl;
        std::cout << "TAG (HEX)(LEN: "<<tagHex.length()<<") : "<< tagHex<<std::endl;
        std::cout << "CHALLENGE (HEX)(LEN: "<<challengeHex.length()<<") : "<< challengeHex<<std::endl;
        //std::cout << "MESSAGE LENTGH: "<< totalMessageLen << std::endl;
        
        
        free(message);
        return 1;
    }
    
     ssize_t receiveEncryptedMsg(
          int socket,
          unsigned char* buffer,
          size_t BUFFER_SIZE,
          std::vector<unsigned char> aesKey,
          std::vector<unsigned char> nonceKey,
          unsigned int &expectedCommSequenceNumber,
          unsigned char *msg
     ){
    
    	
    	
        std::vector<unsigned char> cipherText(MAX_BUFFER_SIZE);
        std::vector<unsigned char> iv(AES_GCM_NONCE_SIZE);
        std::vector<unsigned char> tag(AES_GCM_TAG_SIZE);
        
        std::vector<unsigned char> aadBuffer;
        
        
        
        uint32_t msgLen;
        
        
        size_t bytes_received=recv(socket, &msgLen, sizeof(msgLen), 0);
        if(bytes_received==0){
           //socket closed
           return 0;
        }
        if(bytes_received==-1){
           print_error("Error receiving encrypted message over socket");
           return -1;
        }
        msgLen=ntohl(msgLen);
        //std::cout<<"CipherLen = "<<msgLen<<std::endl;
        
        
        if(msgLen>=BUFFER_SIZE-1){
           print_error("Error reading encrypted message length, it exceed the buffer capacity, possible buffer overflow attack");
           return -1;
        }
        bytes_received=recv(socket, buffer, msgLen, 0);
        if(bytes_received<=0){
           print_error("Error receiving encrypted message over socket");
           return -1;
        }
        buffer[bytes_received]='\0';
        //std::cout << "BYTES REC.: " << bytes_received<<std::endl;
        
        size_t actualCipherLen = bytes_received-AES_GCM_TAG_SIZE-AES_GCM_NONCE_SIZE;
        
        memcpy(cipherText.data(),buffer,actualCipherLen);
        memcpy(iv.data(),buffer+actualCipherLen,AES_GCM_NONCE_SIZE);
        memcpy(tag.data(),buffer+actualCipherLen+AES_GCM_NONCE_SIZE,AES_GCM_TAG_SIZE);
               
	    cipherText.resize(actualCipherLen);
        
        //std::cout << "CYPHERTEXT REC.: " << cipherText.data()<<std::endl;
        //std::cout << "TAG REC.: " << tag.data()<<std::endl;
        //std::cout << "IV REC.: " << iv.data()<<std::endl;
        
        //Verify nonce with communication sequence number avoiding replay
        std::vector<unsigned char> newCommNonce=generateCommunicationNonce(expectedCommSequenceNumber,nonceKey);
        if(memcmp(newCommNonce.data(),iv.data(),12)!=0){
           print_error("Possible replay attack discovered");
           return -2;	
        }
        
        const unsigned char* messageLenBytes = reinterpret_cast<const unsigned char*>(&msgLen);
        aadBuffer.insert(aadBuffer.end(), messageLenBytes, messageLenBytes + sizeof(msgLen));

        aadBuffer.insert(aadBuffer.end(), iv.begin(), iv.end());
        
        //std::cout<<"AAD: ";
        //printHex(aadBuffer.data(),aadBuffer.size());
        
        ssize_t decryptedLen=aes_gcm_decrypt(cipherText.data(),cipherText.size(),aadBuffer.data(),0,tag.data(),aesKey.data(),iv.data(),msg);
        if(decryptedLen==-1){
            std::cerr<<"Error: decrypting message"<<std::endl;
            return -1;
        }
        msg[decryptedLen]='\0';
        
        //std::cout << "MESSAGE REC.: " << msg<<std::endl;
        
        expectedCommSequenceNumber+=1;
        
        return decryptedLen;
    }
    
     int sendEncryptedMessage(
         int socket,
         std::vector<unsigned char> aesKey,
         std::vector<unsigned char> nonceKey,
         unsigned int &commSequenceNumber,
         const unsigned char *message,
         size_t messageLen){
        
        unsigned char encryptedMessage[MAX_BUFFER_SIZE];
        unsigned char cipherText[MAX_BUFFER_SIZE-AES_GCM_TAG_SIZE-AES_GCM_NONCE_SIZE]; 
        unsigned char iv[AES_GCM_NONCE_SIZE];
        unsigned char tag[AES_GCM_TAG_SIZE];
        
        std::vector<unsigned char> aadBuffer;
        size_t finalMsgLen = messageLen+AES_GCM_NONCE_SIZE+AES_GCM_TAG_SIZE;
        
        const unsigned char* messageLenBytes = reinterpret_cast<const unsigned char*>(&finalMsgLen);
        aadBuffer.insert(aadBuffer.end(), messageLenBytes, messageLenBytes + sizeof(finalMsgLen));

        aadBuffer.insert(aadBuffer.end(), iv, iv + AES_GCM_NONCE_SIZE);
        
        //std::cout<<"AAD: ";
        //printHex(aadBuffer.data(),aadBuffer.size());

        // Ensure buffers are clean
        memset(encryptedMessage, 0, sizeof(encryptedMessage));
        memset(cipherText, 0, sizeof(cipherText));
        memset(iv, 0, sizeof(iv));
        memset(tag, 0, sizeof(tag));

        std::vector<unsigned char> nonce=generateCommunicationNonce(commSequenceNumber,nonceKey);
        memcpy(iv,nonce.data(),sizeof(iv));
        
        size_t cipherLen = aes_gcm_encrypt(
            message, messageLen, 
            aadBuffer.data(), 0, 
            aesKey.data(), iv, cipherText, tag
        );
        if(cipherLen<=0){
           print_error("Error occured sending encrypted message, empty ciphertext");
           return -1;
        }
        
        // Assemble the message into the new buffer
        size_t msgLen = 0;
        memcpy(encryptedMessage + msgLen, cipherText, cipherLen);
        msgLen += cipherLen;
        memcpy(encryptedMessage + msgLen, iv, AES_GCM_NONCE_SIZE);
        msgLen += AES_GCM_NONCE_SIZE;
        memcpy(encryptedMessage + msgLen, tag, AES_GCM_TAG_SIZE);
        msgLen += AES_GCM_TAG_SIZE;
        
        //std::cout<<"SENT CL : "<<msgLen<<std::endl;
        
        uint32_t networkLen = htonl(msgLen);
        
        ssize_t sentLen=send(socket, &networkLen, sizeof(networkLen), 0);
        if(sentLen<=0){
           print_error("Error occured sending encrypted message length");
           return -1;
        }
        
        
        sentLen=send(socket, encryptedMessage, msgLen, 0);
        if(sentLen<=0){
           print_error("Error occured sending encrypted message");
           return -1;
        }
        
        commSequenceNumber+=1;
        
        return 1;
        
    }
       
    bool serverEstablishSecureConnection(int clientSocket,EVP_PKEY* serverPrivKey,EVP_PKEY* serverPubKey,DH* dhParams,EVP_PKEY* &clientPubKey,std::vector<unsigned char> &aesKey,std::vector<unsigned char> &nonceKey) {
    
    
    	//STEP 1 RECEIVE CLIENT RSA PUBLIC KEY
    	std::cout << "PHASE 1 HANDSHAKE" << std::endl;
    	

		unsigned char buffer[MAX_BUFFER_SIZE];  // Increased buffer size
	
		memset(buffer, 0, sizeof(buffer));  // Initialize to zero
	
	
		clientPubKey=receiveClientRsaPubKey(clientSocket,buffer,MAX_BUFFER_SIZE);
		if (!clientPubKey){
			print_error("Error occured receiving client rsa public key, exiting");
			return false;
		}
    	
    	memset(buffer, 0, sizeof(buffer));
    	std::cout<<"========================================================================================================"<<std::endl;
        
        // STEP 2: Send server's DH public key and signature
        std::cout<<"PHASE 2, HANDSHAKE"<<std::endl;
        std::cout<<"SENDING SERVER PUBLIC DH KEY"<<std::endl;
        
        const BIGNUM* serverDHPub = DH_get0_pub_key(dhParams);
        if (serverDHPub == NULL) {
    	    print_error("Error: DH_get0_pub_key() failed.");
            return false;
        }
        
        if(sendSignedDHPublicKey(clientSocket,serverDHPub,serverPrivKey)!=1){
            print_error("Error occured sending DH public key, exiting...");
            return false;
        }

	    std::cout<<"========================================================================================================"<<std::endl;
        
        // STEP 3: Receive encrypted client DH public key and signature
        std::cout<<"PHASE 3, HANDSHAKE , RECEIVING PUBLIC DH KEY FROM CLIENT"<<std::endl;
        
        BIGNUM* clientDHPub = nullptr;
        
        clientDHPub=receiveSignedDHPublicKey(clientSocket,buffer,MAX_BUFFER_SIZE,clientPubKey);
        if(!clientDHPub){
        	print_error("Error while receiving dh public key from client, exiting");
        	return false;
        }
        
        
        memset(buffer, 0, sizeof(buffer));
        std::cout<<"HANDSHAKE PHASE 3 COMPLETED"<<std::endl;
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        std::cout<<"COMPUTING SHARED SECRET:"<<std::endl;
        
        // Compute shared secret
        std::vector<unsigned char> sharedSecret = computeDHSharedSecret(dhParams, clientDHPub);
        if (sharedSecret.empty()) {
            print_error("Failed to compute shared secret");
            BN_free(clientDHPub);
            return false;
        }
             
        
        // Print shared secret
        std::cout << "Shared Secret (raw): ";
        for (size_t i = 0; i < sharedSecret.size(); i++) {
            printf("%02x", sharedSecret[i]);
        }
        std::cout << std::endl;
        std::cout << "Shared Secret length: " << sharedSecret.size() << " bytes" << std::endl;
        
        std::vector<unsigned char> salt = {'s', 'a', 'l', 't', '_', 's', 'a', 'l', 't','_', 's', 'a', 'l', 't','_','_'};
        std::vector<unsigned char> encryptionInfo = {'a', 'e', 's', '-', 'k', 'e', 'y'};
        std::vector<unsigned char> authInfo = {'n', 'o', 'n', 'c','e' ,'-', 'k', 'e', 'y'};
        
        // Derive AES key
        aesKey = hkdf_derive(sharedSecret, salt, encryptionInfo, 32);
        if(aesKey.empty()){
            print_error("Error occured deriving AES key");
            BN_free(clientDHPub);
            return false;
        }
        nonceKey = hkdf_derive(sharedSecret, salt, authInfo, 32);
        if(nonceKey.empty()){
            print_error("Error occured deriving Nonce key");
            BN_free(clientDHPub);
            return false;
        }

        std::cout<<std::endl;
        std::cout << "Derived AES Key (256-bit): ";
        printHex(aesKey.data(),32);
        std::cout << std::endl;
        std::cout << "Derived Nonce Key (256-bit): ";
        printHex(nonceKey.data(),32);
        std::cout << std::endl;
        
        
        
          
        memset(buffer, 0, sizeof(buffer));
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 4 HANDSHAKE CHALLENGE
        
        std::cout<<"HANDSHAKE CHALLENGE PHASE, WAITING MESSAGE FROM CLIENT"<<std::endl<<std::endl;
        
        std::vector<unsigned char> challenge(AES_GCM_NONCE_SIZE);
        
        if(receiveChallengeMsg(clientSocket,buffer,MAX_BUFFER_SIZE,aesKey,&challenge)!=1){
            print_error("Error occured receiving challenge msg");
            return false;
        }
        
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 5 SENDING ACK AND SIGNATURE TO CLIENT
        
        std::cout << "HANDSHAKE PHASE 5 SENDING ACK TO CLIENT" << std::endl;
        
        if(sendChallengeMsg(clientSocket,aesKey,&challenge)!=1){
            print_error("Error occured sending challenge msg");
            return false;
        }
        std::cout<<"========================================================================================================"<<std::endl;
        
        
        BN_free(clientDHPub);
        
        return true;
    }
    
    
    bool clientEstablishSecureConnection(const std::string& serverIP, int port,EVP_PKEY* clientPubKey,EVP_PKEY* clientPrvKey,EVP_PKEY* serverPubKey,DH* dhParams,int *serverSocket,std::vector<unsigned char> &aesKey,std::vector<unsigned char> &nonceKey) {
    
        if (!serverPubKey||!clientPubKey||!clientPrvKey) {
            std::cerr << "keys not loaded correctly" << std::endl;
            return false;
        }
        
        *serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (*serverSocket < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
        
        if (connect(*serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Failed to connect to server" << std::endl;
            close(*serverSocket);
            return false;
        }
        
        unsigned char buffer[MAX_BUFFER_SIZE];
        
        std::cout << "Connected to server" << std::endl;
        
        
        //STEP 1 SENDING CLIENT RSA PUBLIC KEY
        std::cout<<"INITIATING HANDSHAKE"<<std::endl;
        std::cout<<"PHASE 1, SENDING CLIENT RSA PUBLIC KEY"<<std::endl;
        
        
        if(sendRsaPublicKey(*serverSocket,clientPubKey)==-1){
            print_error("Failed to send Rsa Public key");
            return false;
        }
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 2 RECEIVING SERVER DH PUBLIC KEY AND SIGNATURE
        std::cout<<"PHASE 2 HANDSHAKE , RECEIVING SERVER DH PUBLIC KEY"<<std::endl;
        
        BIGNUM* serverDHPub = nullptr;
        
        serverDHPub=receiveSignedDHPublicKey(*serverSocket,buffer,MAX_BUFFER_SIZE,serverPubKey);
        if(!serverDHPub){
        	print_error("Error while receiving dh public key from server, exiting");
        	return false;
        }
        
        
        memset(buffer, 0, sizeof(buffer));
        
        std::cout<<"HANDSHAKE PHASE 2 COMPLETED"<<std::endl;
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 3 SENDING CLIENT DH PUBLIC KEY AND SIGNATURE
        
        std::cout<<"PHASE 3 HANDSHAKE"<<std::endl;
        
        
        dhParams=getStandardDHParams();
        // Generate client's DH key pair
        if (!generateDHKeypair(dhParams)) {
            std::cerr << "Failed to generate client DH keypair" << std::endl;
            close(*serverSocket);
            return false;
        }
        std::cout<<"SENDING CLIENT DH PUBKEY TO SERVER"<<std::endl;
        
        const BIGNUM* clientDHPub = DH_get0_pub_key(dhParams);
        
        if(sendSignedDHPublicKey(*serverSocket,clientDHPub,clientPrvKey)!=1){
            print_error("Failed to send DH public key");
            return false;
        }
        

	    std::cout<<"========================================================================================================"<<std::endl;
        
        std::cout << "COMPUTING SHARED SECRET: " << std::endl;
         
        
        // Compute shared secret
        std::vector<unsigned char> sharedSecret = computeDHSharedSecret(dhParams, serverDHPub);
        if (sharedSecret.empty()) {
            std::cerr << "Failed to compute shared secret" << std::endl;
            BN_free(serverDHPub);
            close(*serverSocket);
            return false;
        }
        
        
        std::cout << "Shared Secret (raw): ";
        for (size_t i = 0; i < sharedSecret.size(); i++) {
            printf("%02x", sharedSecret[i]);
        }
        std::cout << std::endl;
        std::cout << "Shared Secret length: " << sharedSecret.size() << " bytes" << std::endl;
        
        std::vector<unsigned char> salt = {'s', 'a', 'l', 't', '_', 's', 'a', 'l', 't','_', 's', 'a', 'l', 't','_','_'};
        std::vector<unsigned char> encryptionInfo = {'a', 'e', 's', '-', 'k', 'e', 'y'};
        std::vector<unsigned char> authInfo = {'n', 'o', 'n', 'c','e' ,'-', 'k', 'e', 'y'};
        
        // Derive AES key
        aesKey = hkdf_derive(sharedSecret, salt, encryptionInfo, 32);
        if(aesKey.empty()){
            print_error("Error occured deriving AES key");
            BN_free(serverDHPub);
            return false;
        }
        nonceKey = hkdf_derive(sharedSecret, salt, authInfo, 32);
        if(nonceKey.empty()){
            print_error("Error occured deriving Nonce key");
            BN_free(serverDHPub);
            return false;
        }

        std::cout<<std::endl;
        std::cout << "Derived AES Key (256-bit): ";
        printHex(aesKey.data(),32);
        std::cout << std::endl;
        std::cout << "Derived Nonce Key (256-bit): ";
        printHex(nonceKey.data(),32);
        std::cout << std::endl;
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 4 HANDSHAKE CHALLENGE
        
        std::cout << "HANDSHAKE CHALLENGE PHASE " << std::endl;
        std::cout << "SENDING CHALLENGE TO SERVER..." << std::endl;
        
        std::vector<unsigned char> challenge;
        
        
        if(sendChallengeMsg(*serverSocket,aesKey,&challenge)!=1){
            print_error("Error occured sending challenge msg");
            return false;
        }
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 5 HANDSHAKE CHALLENGE ACK
        std::cout << "HANDSHAKE CHALLENGE WAITING ACK " << std::endl;
        
        
        std::vector<unsigned char> challenge2(AES_GCM_NONCE_SIZE);
        
        
        if(receiveChallengeMsg(*serverSocket,buffer,MAX_BUFFER_SIZE,aesKey,&challenge2)!=1){
            print_error("Error occured receiving challenge msg");
            return false;
        }
        
        if(memcmp(challenge.data(),challenge2.data(),AES_GCM_NONCE_SIZE)!=0){
            std::cerr<<"Error: challenge mismatch, handshake failed"<<std::endl;
            return false; 
        }
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        
        
        print_green("\n\nKey exchange completed successfully!\n\n");
        
        
        // --- FINAL CLEANUP ---
        BN_free(serverDHPub); // Free the local BIGNUM from the handshake
         
        return true;
    }
    
    bool serverRenegotiateKeys(int clientSocket,EVP_PKEY* serverPrivKey,EVP_PKEY* serverPubKey,EVP_PKEY* clientPubKey,std::vector<unsigned char> &aesKey,std::vector<unsigned char> &nonceKey) {
    
        unsigned char buffer[MAX_BUFFER_SIZE];  // Increased buffer size
	
	    memset(buffer, 0, sizeof(buffer));  // Initialize to zero 
	    
        DH* dhParams=nullptr;
        
    
        
        dhParams=getStandardDHParams();
        // Generate client's DH key pair
        if (!generateDHKeypair(dhParams)) {
            std::cerr << "Failed to generate client DH keypair" << std::endl;
            return false;
        }
            
        std::cout<<"========================================================================================================"<<std::endl;  
        
        std::cout<<"RENEGOTIATION PHASE 1, SENDING SERVER PUBLIC DH KEY"<<std::endl;
        
        const BIGNUM* serverDHPub = DH_get0_pub_key(dhParams);
        if (serverDHPub == NULL) {
    	    print_error("Error: DH_get0_pub_key() failed.");
            DH_free(dhParams);
            return false;
        }
        
        if(sendSignedDHPublicKey(clientSocket,serverDHPub,serverPrivKey)!=1){
            print_error("Error occured sending DH public key, exiting...");
        	DH_free(dhParams);
            return false;
        }

	    std::cout<<"========================================================================================================"<<std::endl;
        
        // STEP 3: Receive encrypted client DH public key and signature
        std::cout<<"RENEGOTIATION PHASE 2, RECEIVING PUBLIC DH KEY FROM CLIENT"<<std::endl;
        
        BIGNUM* clientDHPub = nullptr;
        
        clientDHPub=receiveSignedDHPublicKey(clientSocket,buffer,MAX_BUFFER_SIZE,clientPubKey);
        if(!clientDHPub){
        	print_error("Error while receiving dh public key from client, exiting");
        	DH_free(dhParams);
        	return false;
        }
        
        
        memset(buffer, 0, sizeof(buffer));
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        std::cout<<"COMPUTING SHARED SECRET"<<std::endl;
        
        // Compute shared secret
        std::vector<unsigned char> sharedSecret = computeDHSharedSecret(dhParams, clientDHPub);
        if (sharedSecret.empty()) {
            print_error("Failed to compute shared secret");
            BN_free(clientDHPub);
        	DH_free(dhParams);
            return false;
        }
             
        
        // Print shared secret
        std::cout << "\n=== SERVER SIDE ===" << std::endl;
        std::cout << "Shared Secret (raw): ";
        for (size_t i = 0; i < sharedSecret.size(); i++) {
            printf("%02x", sharedSecret[i]);
        }
        std::cout << std::endl;
        std::cout << "Shared Secret length: " << sharedSecret.size() << " bytes" << std::endl;
        
        std::vector<unsigned char> salt = {'s', 'a', 'l', 't', '_', 's', 'a', 'l', 't','_', 's', 'a', 'l', 't','_','_'};
        std::vector<unsigned char> encryptionInfo = {'a', 'e', 's', '-', 'k', 'e', 'y'};
        std::vector<unsigned char> authInfo = {'n', 'o', 'n', 'c','e' ,'-', 'k', 'e', 'y'};
        
        // Derive AES key
        aesKey = hkdf_derive(sharedSecret, salt, encryptionInfo, 32);
        if(aesKey.empty()){
            print_error("Error occured deriving AES key");
            BN_free(clientDHPub);
        	DH_free(dhParams);
            return false;
        }
        nonceKey = hkdf_derive(sharedSecret, salt, authInfo, 32);
        if(nonceKey.empty()){
            print_error("Error occured deriving Nonce key");
            BN_free(clientDHPub);
        	DH_free(dhParams);
            return false;
        }

        std::cout << std::endl;
        std::cout << "Derived AES Key (256-bit): ";
        printHex(aesKey.data(),32);
        std::cout << std::endl;
        std::cout << "Derived Nonce Key (256-bit): ";
        printHex(nonceKey.data(),32);
        std::cout << std::endl;
        
        
        
          
        memset(buffer, 0, sizeof(buffer));
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 4 HANDSHAKE CHALLENGE
        
        std::cout<<"HANDSHAKE CHALLENGE PHASE, WAITING MESSAGE FROM CLIENT"<<std::endl;
        
        std::vector<unsigned char> challenge(AES_GCM_NONCE_SIZE);
        
        if(receiveChallengeMsg(clientSocket,buffer,MAX_BUFFER_SIZE,aesKey,&challenge)!=1){
            print_error("Error occured receiving challenge msg");
            BN_free(clientDHPub);
        	DH_free(dhParams);
            return false;
        }
        
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 5 SENDING ACK AND SIGNATURE TO CLIENT
        
        std::cout << "HANDSHAKE PHASE 5 SENDING ACK TO CLIENT" << std::endl;
        
        if(sendChallengeMsg(clientSocket,aesKey,&challenge)!=1){
            print_error("Error occured sending challenge msg");
            BN_free(clientDHPub);
        	DH_free(dhParams);
            return false;
        }
        std::cout<<"========================================================================================================"<<std::endl;
        
        
        BN_free(clientDHPub);
        DH_free(dhParams);
        
        return true;
    
    }
    
    bool clientRenegotiateKeys(int serverSocket,EVP_PKEY* clientPubKey,EVP_PKEY* clientPrvKey,EVP_PKEY* serverPubKey,std::vector<unsigned char> &aesKey,std::vector<unsigned char> &nonceKey) {
    
        
        DH* dhParams=nullptr;
        
        
        unsigned char buffer[MAX_BUFFER_SIZE];
        
        
        std::cout << "Renegotiating keys" << std::endl;
        
       
        std::cout<<"RENEGOTIATION PHASE 1 , RECEIVING SERVER DH PUBLIC KEY"<<std::endl;
        
        BIGNUM* serverDHPub = nullptr;
        
        serverDHPub=receiveSignedDHPublicKey(serverSocket,buffer,MAX_BUFFER_SIZE,serverPubKey);
        if(!serverDHPub){
        	print_error("Error while receiving dh public key from server, exiting");
        	return false;
        }
        
        
        memset(buffer, 0, sizeof(buffer));
        
        std::cout<<"RENEGOTIATION PHASE 1 COMPLETED"<<std::endl;
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        
        
        std::cout<<"RENEGOTIATION PHASE 2, SENDING CLIENT DH PUBLIC KEY AND SIGNATURE"<<std::endl;
        
        
        dhParams=getStandardDHParams();
        // Generate client's DH key pair
        if (!generateDHKeypair(dhParams)) {
            std::cerr << "Failed to generate client DH keypair" << std::endl;
            BN_free(serverDHPub);
            close(serverSocket);
            return false;
        }
        std::cout<<"SENDING CLIENT DH PUBKEY TO SERVER"<<std::endl;
        
        const BIGNUM* clientDHPub = DH_get0_pub_key(dhParams);
        
        if(sendSignedDHPublicKey(serverSocket,clientDHPub,clientPrvKey)!=1){
            print_error("Failed to send DH public key");
            BN_free(serverDHPub);
            DH_free(dhParams);
            close(serverSocket);
            return false;
        }
        

	    std::cout<<"========================================================================================================"<<std::endl;
        
        std::cout << "COMPUTING SHARED SECRET: " << std::endl;
         
        
        // Compute shared secret
        std::vector<unsigned char> sharedSecret = computeDHSharedSecret(dhParams, serverDHPub);
        if (sharedSecret.empty()) {
            std::cerr << "Failed to compute shared secret" << std::endl;
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket);
            return false;
        }
        
        // Print shared secret
        std::cout << "\n=== CLIENT SIDE ===" << std::endl;
        std::cout << "Shared Secret (raw): ";
        for (size_t i = 0; i < sharedSecret.size(); i++) {
            printf("%02x", sharedSecret[i]);
        }
        std::cout << std::endl;
        std::cout << "Shared Secret length: " << sharedSecret.size() << " bytes" << std::endl;
        
        std::vector<unsigned char> salt = {'s', 'a', 'l', 't', '_', 's', 'a', 'l', 't','_', 's', 'a', 'l', 't','_','_'};
        std::vector<unsigned char> encryptionInfo = {'a', 'e', 's', '-', 'k', 'e', 'y'};
        std::vector<unsigned char> authInfo = {'n', 'o', 'n', 'c','e' ,'-', 'k', 'e', 'y'};
        
        // Derive AES key
        aesKey = hkdf_derive(sharedSecret, salt, encryptionInfo, 32);
        if(aesKey.empty()){
            print_error("Error occured deriving AES key");
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket);
            return false;
        }
        nonceKey = hkdf_derive(sharedSecret, salt, authInfo, 32);
        if(nonceKey.empty()){
            print_error("Error occured deriving Nonce key");
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket);
            return false;
        }

        std::cout << std::endl;
        std::cout << "Derived AES Key (256-bit): ";
        printHex(aesKey.data(),32);
        std::cout << std::endl;
        std::cout << "Derived Nonce Key (256-bit): ";
        printHex(nonceKey.data(),32);
        std::cout << std::endl;
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 4 HANDSHAKE CHALLENGE
        
        std::cout << "HANDSHAKE CHALLENGE PHASE " << std::endl;
        std::cout << "SENDING CHALLENGE TO SERVER..." << std::endl;
        
        std::vector<unsigned char> challenge;
        
        
        if(sendChallengeMsg(serverSocket,aesKey,&challenge)!=1){
            print_error("Error occured sending challenge msg");
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket);
        }
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        //STEP 5 HANDSHAKE CHALLENGE ACK
        std::cout << "HANDSHAKE CHALLENGE WAITING ACK " << std::endl;
        
        
        std::vector<unsigned char> challenge2(AES_GCM_NONCE_SIZE);
        
        
        if(receiveChallengeMsg(serverSocket,buffer,MAX_BUFFER_SIZE,aesKey,&challenge2)!=1){
            print_error("Error occured receiving challenge msg");
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket);
        }
        
        if(memcmp(challenge.data(),challenge2.data(),AES_GCM_NONCE_SIZE)!=0){
            std::cerr<<"Error: challenge mismatch, handshake failed"<<std::endl;
        	BN_free(serverDHPub);
        	DH_free(dhParams);
            close(serverSocket); 
        }
        
        
        std::cout<<"========================================================================================================"<<std::endl;
        
        
        
        std::cout << "Key exchange completed successfully!" << std::endl;
        
        
        // --- FINAL CLEANUP ---
        BN_free(serverDHPub);
        DH_free(dhParams);
         
        return true;
    }

#endif

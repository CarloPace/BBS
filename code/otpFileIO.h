#ifndef OTPFILEIO_H
#define OTPFILEIO_H

#include <fstream>  // For std::ofstream
#include <string>
#include <iostream>   // For std::string

int writeOtpOnFile(std::string username,std::string otp){

    const std::string fileName=username+"Otp.txt";
    // Create an ofstream object and open the file
    std::ofstream outFile(fileName);

    // Check if the file was opened successfully
    if (!outFile) {
        std::cerr << "Error opening file: " << fileName << std::endl;
        return 1; // Return a non-zero value to indicate error
    }

    // Write the string to the file
    outFile << otp;

    // Optionally, flush the stream to ensure all data is written
    outFile.flush();

    // Close the file
    outFile.close();

    return 0;
}

int readOtpFromFile(std::string username,std::string *otp){

    const std::string fileName=username+"Otp.txt";
    // Create an instream object and open the file
    std::ifstream inFile(fileName);

    // Check if the file was opened successfully
    if (!inFile) {
        std::cerr << "Error opening file: " << fileName << std::endl;
        return 1; // Return a non-zero value to indicate error
    }

    std::string line;
    // Read the file line by line
    while (std::getline(inFile, line)) {
        std::cout << line << std::endl;
    }
    // Close the file
    inFile.close();
    *otp=line;

    return 0;
}
#endif
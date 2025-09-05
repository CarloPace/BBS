#include "message.h"
#include <cstring>



Message::Message(){
    this->title="xxxx";
    this->author="xxxx";
    this->body="xxxx";
    this->mid=0;
}

Message::Message(const int mid,const char title[TITLE_LENGTH],const char author[AUTHOR_LENGTH],const char body[BODY_LENGTH]){
    this->mid=mid;
    this->title=title;
    this->author=author;
    this->body=body;
}

int Message::getMid() const{
    return this->mid;
}

std::string Message::getTitle() const{
    return this->title;
}

std::string Message::getAuthor() const{
    return this->author;
}

std::string Message::getBody() const{
    return this->body;
}

void Message::setId(const int mid){
    this->mid=mid;
}

void Message::setTitle(const char title[TITLE_LENGTH]){
    this->title=title;
}

void Message::setAuthor(const char author[AUTHOR_LENGTH]){
    this->author=author;
}

void Message::setBody(const char body[BODY_LENGTH]){
    this->body=body;
}

std::string Message::toString() const{
        return "Title:" + this->title + "\nAuthor:" + this->author + "\nBody:"+ this->body;
}


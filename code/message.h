// message.h
#ifndef MESSAGE_H
#define MESSAGE_H

#define TITLE_LENGTH 64
#define AUTHOR_LENGTH 32
#define BODY_LENGTH 1024

#include <array>
#include <string>


class Message {
private:
    int mid;
    std::string title;
    std::string author;
    std::string body;

public:
    Message();
    Message(const int mid,const char title [TITLE_LENGTH],const char author [AUTHOR_LENGTH],const char body[BODY_LENGTH]);

    int getMid() const;
    std::string getTitle() const;
    std::string getAuthor() const;
    std::string getBody() const;

    void setId(const int mid);
    void setTitle(const char title[TITLE_LENGTH]);
    void setAuthor(const char author[AUTHOR_LENGTH]);
    void setBody(const char author[BODY_LENGTH]);

    std::string toString() const;
};

#endif

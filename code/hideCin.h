#ifndef HIDECIN_H
#define HIDECIN_H

#include <termios.h>
#include <iostream> // To use 'std::cout' and 'std::cin'
#include <termios.h> // To use 'termios' and 'tcsetattr'
#include <unistd.h> // To use 'STDIN_FILENO'

void HideStdinKeystrokes()
{
    termios tty;

    tcgetattr(STDIN_FILENO, &tty);

    /* we want to disable echo */
    tty.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void ShowStdinKeystrokes()
{
   termios tty;

    tcgetattr(STDIN_FILENO, &tty);

    /* we want to reenable echo */
    tty.c_lflag |= ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
};

#endif
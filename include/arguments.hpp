// arguments.hpp
#ifndef ARGUMENTS_HPP
#define ARGUMENTS_HPP

#include <string>

struct ProgramOptions {
    std::string vaultFile;
    bool changePass = false;
    bool showHelp = false;
};

ProgramOptions resolveArguments(int argc, char* argv[]);

#endif

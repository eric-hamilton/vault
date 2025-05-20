// arguments.cpp
#include "arguments.hpp"
#include <cstdlib>
#include <string>
#include <iostream>

ProgramOptions resolveArguments(int argc, char* argv[]) {
    ProgramOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--change_pass") {
            opts.changePass = true;
        } else if (arg == "--filepath" && i + 1 < argc) {
            opts.vaultFile = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            opts.showHelp = true;
        } else if (opts.vaultFile.empty()) {
            // Assume it's a positional filename
            opts.vaultFile = arg;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            opts.showHelp = true;
        }
    }

    // If no path specified, try environment variable
    if (opts.vaultFile.empty()) {
        const char* env_path = std::getenv("VAULT_FILE");
        if (env_path) {
            opts.vaultFile = env_path;
        } else {
            // Fall back to default
            opts.vaultFile = "vault.dat";
        }
    }

    return opts;
}
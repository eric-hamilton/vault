#include <algorithm>
#include <fstream>
#include <cstdlib>
#include <string>
#include <cstdio>      // std::remove
#include <filesystem>
#include <random>
#include <iostream>

std::string generate_temp_filename() {
    std::string temp_dir = std::getenv("TEMP") ? std::getenv("TEMP") : ".";
    if (temp_dir.back() != '/' && temp_dir.back() != '\\') {
        temp_dir += "/";
    }

    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string random_str;
    std::default_random_engine rng{std::random_device{}()};
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    for (int i = 0; i < 8; ++i) {
        random_str += chars[dist(rng)];
    }

    // Use forward slashes for compatibility with nano in Bash
    std::string filename = temp_dir + "vault_tmp_" + random_str + ".txt";
    std::replace(filename.begin(), filename.end(), '\\', '/');
    return filename;
}

std::string launch_editor(const std::string& initial_content) {
    std::string tmp_file = generate_temp_filename();

    // Write initial content
    {
        std::ofstream ofs(tmp_file);
        ofs << initial_content;
    }

    // Launch editor (nano expected)
    std::system(("nano " + tmp_file).c_str());

    // Read the edited content
    std::string result;
    {
        std::ifstream ifs(tmp_file);
        std::string line;
        while (std::getline(ifs, line)) {
            result += line + "\n";
        }
    }

    // Delete the file
    if (std::remove(tmp_file.c_str()) != 0) {
        std::cerr << "Warning: Failed to delete temp file: " << tmp_file << std::endl;
    }

    return result;
}

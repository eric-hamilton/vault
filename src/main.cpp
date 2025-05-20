#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <sys/stat.h>
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "arguments.hpp"
#include "editor.hpp"

const int SALT_LEN = 16;
const int KEY_LEN = 32;
const int IV_LEN = 16;
const int PBKDF2_ITERATIONS = 100000;
const std::string HEADER = "# VAULT";

void change_passphrase(const std::string& filename);

// Utility to read a password silently (Windows-only)
std::string getpass(const std::string& prompt) {
    std::cout << prompt;
    std::string password;

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    std::getline(std::cin, password);

    SetConsoleMode(hStdin, mode);
    std::cout << std::endl;

    return password;
}

// Derive key using PBKDF2
bool derive_key(const std::string& pass, const unsigned char* salt, unsigned char* key) {
    return PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, key);
}

// Encrypt data using AES-256-CBC
std::vector<unsigned char> encrypt(const std::string& plaintext, const std::string& pass) {
    std::vector<unsigned char> salt(SALT_LEN);
    std::vector<unsigned char> iv(IV_LEN);
    std::vector<unsigned char> key(KEY_LEN);

    RAND_bytes(salt.data(), SALT_LEN);
    RAND_bytes(iv.data(), IV_LEN);
    derive_key(pass, salt.data(), key.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    std::vector<unsigned char> output;
    output.insert(output.end(), salt.begin(), salt.end());
    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    return output;
}

// Decrypt data
std::string decrypt(const std::vector<unsigned char>& input, const std::string& pass) {
    if (input.size() < SALT_LEN + IV_LEN) return "";

    std::vector<unsigned char> salt(input.begin(), input.begin() + SALT_LEN);
    std::vector<unsigned char> iv(input.begin() + SALT_LEN, input.begin() + SALT_LEN + IV_LEN);
    std::vector<unsigned char> ciphertext(input.begin() + SALT_LEN + IV_LEN, input.end());

    std::vector<unsigned char> key(KEY_LEN);
    derive_key(pass, salt.data(), key.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return std::string(plaintext.begin(), plaintext.end());
}

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

#include "arguments.hpp"

int main(int argc, char** argv) {
    auto opts = resolveArguments(argc, argv);
    std::string VAULT_FILE = opts.vaultFile;

    if (opts.showHelp) {
        std::cout << "Usage: vault.exe [--filepath <file>] [--change_pass]" << std::endl;
        return 1;
    }

    std::cout << "Using vault: " << opts.vaultFile << std::endl;

    if (opts.changePass) {
        change_passphrase(opts.vaultFile);
        return 0;
    }

    std::string pass = getpass("Enter passphrase: ");
    std::string editable;

    if (file_exists(VAULT_FILE)) {
        std::ifstream in(VAULT_FILE, std::ios::binary);
        std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(in)), {});
        in.close();

        std::string plaintext = decrypt(file_data, pass);
        std::istringstream iss(plaintext);
        std::string header;
        std::getline(iss, header);

        if (header != HEADER) {
            std::cerr << "Invalid vault file. Decryption failed or header missing." << std::endl;
            return 1;
        }

        editable.assign(std::istreambuf_iterator<char>(iss), {});
    } else {
        editable = "New vault";
    }

    std::string edited = launch_editor(editable);
    std::string final_content = HEADER + "\n" + edited;

    std::vector<unsigned char> encrypted = encrypt(final_content, pass);
    std::ofstream out(VAULT_FILE, std::ios::binary);
    out.write(reinterpret_cast<char*>(encrypted.data()), encrypted.size());
    out.close();

    std::cout << "Vault saved successfully." << std::endl;
    return 0;
}

void change_passphrase(const std::string& filename) {
    if (!std::ifstream(filename)) {
        std::cerr << "Vault file does not exist: " << filename << std::endl;
        return;
    }

    std::string current_pass = getpass("Enter current passphrase: ");

    std::ifstream in(filename, std::ios::binary);
    std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::string plaintext;
    try {
        plaintext = decrypt(file_data, current_pass);
    } catch (...) {
        std::cerr << "Decryption failed. Incorrect passphrase?" << std::endl;
        return;
    }

    std::istringstream iss(plaintext);
    std::string header;
    std::getline(iss, header);
    if (header != HEADER) {
        std::cerr << "Invalid vault header." << std::endl;
        return;
    }

    std::string new_pass1 = getpass("Enter new passphrase: ");
    std::string new_pass2 = getpass("Re-enter new passphrase: ");
    if (new_pass1 != new_pass2) {
        std::cerr << "Passwords do not match." << std::endl;
        return;
    }

    std::vector<unsigned char> encrypted = encrypt(plaintext, new_pass1);
    std::ofstream out(filename, std::ios::binary);
    out.write(reinterpret_cast<char*>(encrypted.data()), encrypted.size());
    out.close();

    std::cout << "Passphrase changed successfully." << std::endl;
}

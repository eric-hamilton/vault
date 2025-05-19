#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <termios.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/stat.h>

// Configuration
const std::string VAULT_FILE = "vault.dat";
const std::string TEMP_FILE = "/tmp/vault_edit.tmp";
const int SALT_LEN = 16;
const int KEY_LEN = 32;
const int IV_LEN = 16;
const int PBKDF2_ITERATIONS = 100000;

// Utility to read a password silently
std::string getpass(const std::string& prompt) {
    std::cout << prompt;
    termios oldt, newt;
    std::string password;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
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

int main(int argc, char** argv) {
    std::string pass = getpass("Enter passphrase: ");
    std::vector<unsigned char> file_data;

    if (file_exists(VAULT_FILE)) {
        std::ifstream in(VAULT_FILE, std::ios::binary);
        file_data.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::string plaintext = decrypt(file_data, pass);
        if (plaintext.empty()) {
            std::cerr << "Failed to decrypt file. Wrong password?" << std::endl;
            return 1;
        }

        std::ofstream tmp(TEMP_FILE);
        tmp << plaintext;
        tmp.close();
    } else {
        std::ofstream tmp(TEMP_FILE);
        tmp << "# New vault\n";
        tmp.close();
    }

    std::string editor = std::getenv("EDITOR") ? std::getenv("EDITOR") : "nano";
    std::string command = editor + " " + TEMP_FILE;
    std::system(command.c_str());

    std::ifstream tmp_in(TEMP_FILE);
    std::string edited((std::istreambuf_iterator<char>(tmp_in)), std::istreambuf_iterator<char>());
    tmp_in.close();

    std::vector<unsigned char> encrypted = encrypt(edited, pass);
    std::ofstream out(VAULT_FILE, std::ios::binary);
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();

    std::remove(TEMP_FILE.c_str());
    std::cout << "Vault saved successfully." << std::endl;
    return 0;
}

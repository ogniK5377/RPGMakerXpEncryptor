#include <array>
#include <filesystem>
#include <iostream>
#include <Windows.h>
#include <strsafe.h>

#ifdef _MSC_VER
// 64 bit offsets for MSVC
#define fseeko _fseeki64
#define ftello _ftelli64
#define fileno _fileno
#endif

unsigned int KEY = 0xdeadcafe;
namespace fs = std::filesystem;

void ErrorPrinter() {
    // Convert GetLastError() to an actual string using the windows api
    LPVOID message_buffer{};
    const auto last_error = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  reinterpret_cast<LPTSTR>(&message_buffer), 0, NULL);
    if (message_buffer == nullptr) {
        return;
    }

    std::cerr << std::string(static_cast<LPCTSTR>(message_buffer)) << std::endl;
    LocalFree(message_buffer);
}

// Routine for encrypting file data
void EncryptData(char* data, std::size_t len) {
    unsigned int tmp_key = KEY;
    for (std::size_t i = 0; i < len; i++) {
        const std::size_t key_index = i % 4;
        if (i != 0 && key_index == 0) {
            tmp_key = 7 * tmp_key + 3;
        }
        data[i] ^= (tmp_key >> (i * 8)) & 0xff;
    }
}

// Routine for encrypting path and data lengths
unsigned int EncryptUInt(unsigned int n) {
    n ^= KEY;
    KEY = 7 * KEY + 3;
    return n;
}

// Routine for encrypting the path
void EncryptString(char* data, std::size_t len) {
    for (std::size_t i = 0; i < len; i++) {
        data[i] ^= KEY & 0xff;
        KEY = 7 * KEY + 3;
    }
}

struct RGSSADSection {
    unsigned int path_length{};
    std::vector<char> path{};
    unsigned int data_length{};
    std::vector<char> data{};

    // Pre-encrypt all the data in our constructor so we can just write directly to the file
    RGSSADSection(const std::string& _path, std::vector<char>& _data) {
        path_length = EncryptUInt(static_cast<unsigned int>(_path.length()));
        std::copy(_path.begin(), _path.end(), std::back_inserter(path));
        EncryptString(path.data(), path.size());

        data_length = EncryptUInt(static_cast<unsigned int>(_data.size()));
        data.resize(_data.size());
        std::memcpy(data.data(), _data.data(), data.size());
        EncryptData(data.data(), data.size());
    }

    // Write to file
    void WriteToFile(FILE* fp) {
        fwrite(&path_length, sizeof(unsigned int), 1, fp);
        fwrite(path.data(), sizeof(char), path.size(), fp);
        fwrite(&data_length, sizeof(unsigned int), 1, fp);
        fwrite(data.data(), sizeof(char), data.size(), fp);
    }
};

bool PackRgssad(const std::string& base, std::size_t trim_size, FILE* rgssad) {
    // Scan the folder for any files & folders
    for (const auto& entry : fs::directory_iterator(base)) {
        if (entry.is_directory()) {
            // If we're a directory, recurse till we get all the files
            if (!PackRgssad(entry.path().string(), trim_size, rgssad)) {
                // We failed somewhere, jump out!
                return false;
            }
        } else if (entry.is_regular_file()) {
            // IF we're a regular file
            const std::string file_path = entry.path().string();
            const std::string trimmed_file_path =
                file_path.substr(trim_size); // Instead of parsing the path, we just take a
                                             // substring to get the relative path

            std::cout << trimmed_file_path << std::endl;

            // Open the file we want to encrypt and pack
            FILE* fp = nullptr;
            const auto err = fopen_s(&fp, file_path.c_str(), "rb");
            if (err || fp == nullptr) {
                std::cerr << "Failed to open file!" << std::endl;
                ErrorPrinter();
                return false;
            }

            // Get our file size
            fseeko(fp, 0, SEEK_END);
            const auto file_length = static_cast<unsigned int>(ftello(fp));
            fseeko(fp, 0, SEEK_SET);

            // Read the file data
            std::vector<char> data(file_length);
            fread(data.data(), sizeof(char), data.size(), fp);
            fclose(fp);

            // Encrypt and write to our RGSSAD
            RGSSADSection section(trimmed_file_path, data);
            section.WriteToFile(rgssad);
        }
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << argv[0] << " <input path> [output file]" << std::endl;
        return 1;
    }

    //
    const std::string input_path(
        std::filesystem::canonical(std::filesystem::absolute(argv[1])).string());
    if (!std::filesystem::is_directory(input_path)) {
        // Argument is not a directory
        std::cerr << "\"" << input_path << "\" is not a valid directory";
    }

    // By default, write our archive to the game folder
    std::string output_path(input_path + "\\Game.rgssad");

    // Unless we specify a location we want to save it
    if (argc > 2) {
        output_path = std::filesystem::absolute(argv[2]).string();
    }

    // Open our RGSSAD file
    FILE* fp = nullptr;
    const auto err = fopen_s(&fp, output_path.c_str(), "wb");
    if (err || fp == nullptr) {
        std::cerr << "Failed to create file " << output_path << std::endl;
        ErrorPrinter();
        return 1;
    }

    // Write the predefined header(this doesn't change)
    constexpr std::array<char, 8> header{{'R', 'G', 'S', 'S', 'A', 'D', '\0', '\x01'}};
    fwrite(header.data(), sizeof(char), header.size(), fp);

    // Only search through the Data and Graphics folder. We cannot add audio to the encrypted
    // archive as RPG Makers audio engine doesn't seem to search it
    constexpr std::array<const char*, 2> search_directories{{"Data", "Graphics"}};

    const std::size_t trim_size = input_path.length() + 1;
    for (const auto& dir : search_directories) {
        // Scan for files and pack them into the RGSSAD
        if (!PackRgssad(std::filesystem::canonical(input_path + "\\" + dir).string(), trim_size,
                        fp)) {
            std::cerr << "Failed to pack RGSSAD!" << std::endl;
            fclose(fp);
            // Delete the encrypted file as it would be corrupted
            fs::remove(output_path);
            break;
        }
    }
    fclose(fp);

    return 0;
}

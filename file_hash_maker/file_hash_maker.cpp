
#include <iostream>
#include "openssl_wrapper.h"

#define MAX_PATH_LEN 256

char inputFileName[MAX_PATH_LEN] = "input.bin";
char outputFileName[MAX_PATH_LEN] = "output.txt";
uint32_t blockSizeInChar = 1024 * 1024;

std::shared_ptr<FILE> inputFile, outputFile;

void readFromKeyboard()
{
    std::cout << "input file: ";
    std::cin >> inputFileName;

    std::cout << "output file: ";
    std::cin >> outputFileName;

    std::cout << "block size: ";
    std::cin >> blockSizeInChar;
}

auto closeFile = [](FILE* ptr)
{
    fflush(ptr);
    fclose(ptr);
};

bool OpenFile()
{
    FILE* pFile = nullptr;
    if (fopen_s(&pFile, inputFileName, "rb") || !pFile)
        return false;

    inputFile.reset(pFile, closeFile);

    pFile = nullptr;
    if (fopen_s(&pFile, outputFileName, "wb+") || !pFile)
        return false;

    outputFile.reset(pFile, closeFile);

    return true;
}

bool WriteHash(std::unique_ptr<unsigned char[]> pValue, uint32_t size)
{
    if (size != fwrite(pValue.get(), sizeof(unsigned char), size, outputFile.get()))
        return false;

    return true;
}

bool CalcHash()
{
    size_t readBytes = 0;
    std::unique_ptr<unsigned char[]> inputBuffer = nullptr;
    std::unique_ptr<unsigned char[]> md5digest = nullptr;

    do
    {
        auto inputBuffer = std::make_unique<unsigned char[]>(blockSizeInChar);

        readBytes = fread_s(inputBuffer.get(), blockSizeInChar, sizeof(unsigned char), blockSizeInChar, inputFile.get());
        if (!readBytes)
            break; //EOF

        try
        {
            md5digest = MD5Hash::CalsHash(std::move(inputBuffer), blockSizeInChar);
        }
        catch (MD5Exception& e)
        {
            std::cout << "Got an exception from MD5 calculator: " << e.what() << "\n";
            return false;
        }

        if (!WriteHash(std::move(md5digest), MD5_DIGEST_LENGTH))
            return false;

    } while (readBytes == blockSizeInChar);


    return true;
}


int main()
{
    //readFromKeyboard();

    if (!OpenFile())
        return -1;

    (void)CalcHash();

    inputFile.reset();
    outputFile.reset();

    return 0;
}

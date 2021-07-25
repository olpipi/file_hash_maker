
#include <iostream>
#include <openssl/md5.h>

#define MAX_PATH_LEN 256

char inputFileName[MAX_PATH_LEN] = "input.bin";
char outputFileName[MAX_PATH_LEN] = "output.txt";
uint32_t blockSizeInByte = 1024 * 1024;

std::shared_ptr<FILE> inputFile, outputFile;

void readFromKeyboard()
{
    std::cout << "input file: ";
    std::cin >> inputFileName;

    std::cout << "output file: ";
    std::cin >> outputFileName;

    std::cout << "block size: ";
    std::cin >> blockSizeInByte;
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

bool WriteHash(unsigned char* value)
{
    if (MD5_DIGEST_LENGTH != fwrite(value, 1, MD5_DIGEST_LENGTH, outputFile.get()))
        return false;

    return true;
}

bool CalcHash()
{
    char* inputBuffer = new char[blockSizeInByte];

    MD5_CTX md5handler = {};
    unsigned char md5digest[MD5_DIGEST_LENGTH] = {};

    while (blockSizeInByte == fread_s(inputBuffer, blockSizeInByte, sizeof(char), blockSizeInByte, inputFile.get()))
    {
        if (1 != MD5_Init(&md5handler))
            return false;
        if (1 != MD5_Update(&md5handler, static_cast<const void*>(inputBuffer), blockSizeInByte))
            return false;
        if (1 != MD5_Final(md5digest, &md5handler))
            return false;

        if (!WriteHash(md5digest))
            return false;
    }

    if (1 != MD5_Init(&md5handler))
        return false;
    if (1 != MD5_Update(&md5handler, static_cast<const void*>(inputBuffer), blockSizeInByte))
        return false;
    if (1 != MD5_Final(md5digest, &md5handler))
        return false;

    if (!WriteHash(md5digest))
        return false;

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

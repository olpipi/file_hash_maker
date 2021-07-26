
#include <iostream>
#include <deque>
#include <queue>
#include <mutex>
#include <thread>

#include "openssl_wrapper.h"

#define MAX_PATH_LEN 256

char inputFileName[MAX_PATH_LEN] = "input.bin";
char outputFileName[MAX_PATH_LEN] = "output.txt";
uint32_t blockSizeInChar = 1024 * 1024;

std::shared_ptr<FILE> inputFile, outputFile;

void closeFile(FILE* ptr)
{
    fclose(ptr);
};

void readFromKeyboard()
{
    std::cout << "input file: ";
    std::cin >> inputFileName;

    std::cout << "output file: ";
    std::cin >> outputFileName;

    std::cout << "block size: ";
    std::cin >> blockSizeInChar;
}



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

struct Task
{
    std::unique_ptr<unsigned char[]> inputBuffer;
    uint32_t index;

    Task(uint32_t blockSizeInChar, uint32_t index)
    {
        this->index = index;
        inputBuffer = std::make_unique<unsigned char[]>(blockSizeInChar);
    }
    Task() = delete;
};

std::queue<std::unique_ptr<Task>> taskQueue;
std::mutex taskQueueMutex;

std::vector<std::pair<uint32_t, std::unique_ptr<unsigned char[]>>> hashVector;
std::mutex hashVectorMutex;

std::condition_variable cv;


void producer()
{
    size_t readBytes = 0;

    for (uint32_t index = 0;; index++)
    {
        auto newTask = std::make_unique<Task>(blockSizeInChar, index);
        readBytes = fread_s(newTask->inputBuffer.get(), blockSizeInChar, sizeof(unsigned char), blockSizeInChar, inputFile.get());
        
        if (!readBytes)
            break;
        {
            std::lock_guard<std::mutex> lock{ taskQueueMutex };
            taskQueue.push(std::move(newTask));
        }

        cv.notify_one();
    }

    {
        std::lock_guard<std::mutex> lock{ taskQueueMutex };
        taskQueue.push(nullptr);
    }
    cv.notify_all();
}

void consumer() {
    std::unique_ptr<Task> newTask = nullptr;
    std::unique_ptr<unsigned char[]> md5digest = nullptr;

    for (;;)
    {
        {
            std::unique_lock<std::mutex> lock{ taskQueueMutex };
            cv.wait(lock, []
                {
                    return !taskQueue.empty();
                });

            newTask = std::move(taskQueue.front());
            if (newTask == nullptr)
                break; //do not get nullptr task from queue to stop other consumers
            taskQueue.pop();
        }

        try
        {
            md5digest = MD5Hash::CalsHash(std::move(newTask->inputBuffer), blockSizeInChar);
        }
        catch (MD5Exception& e)
        {
            std::cout << "Got an exception from MD5 calculator: " << e.what() << "\n";
            return;
        }

        {
            std::lock_guard<std::mutex> lock(hashVectorMutex);
            hashVector.emplace_back(newTask->index, std::move(md5digest));
        }

    }
}




int main()
{
    uint32_t numThreads = 4;
    //readFromKeyboard();

    if (!OpenFile())
        return -1;

    std::thread prod(&producer);

    std::vector<std::thread> cons;
    for (uint32_t i = 0; i < numThreads; i++) {
        cons.emplace_back([] {consumer();});
    }

    prod.join();
    for (uint32_t i = 0; i < numThreads; i++)
        cons[i].join();

    auto qq = hashVector[0].first;

    std::sort(hashVector.begin(), hashVector.end(), [](auto& left, auto& right) {
        return left.first < right.first; });

    for (uint32_t i = 0; i < hashVector.size(); i++)
    {
        WriteHash(std::move(hashVector[i].second), MD5_DIGEST_LENGTH);
    }

    inputFile.reset();
    outputFile.reset();

    return 0;
}

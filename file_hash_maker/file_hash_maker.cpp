
#include <iostream>
#include <deque>
#include <queue>
#include <mutex>
#include <thread>
#include <execution>
#include "openssl_wrapper.h"

#define MAX_PATH_LEN 256

char inputFileName[MAX_PATH_LEN] = "input.bin";
char outputFileName[MAX_PATH_LEN] = "output.txt";
uint32_t blockSizeInChar = 1024 * 1024 * 50;

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

std::condition_variable cvNewTask;
std::condition_variable cvTaskDone;

std::atomic<bool> stoppedFlag{ false };

uint32_t memoryLimitInMb = 100;
//uint32 is enough up to 4GB

void producer()
{
    uint32_t maxTaskCount = (memoryLimitInMb * 1024 * 1024) / (blockSizeInChar * sizeof(unsigned char));

    size_t readBytes = 0;

    for (uint32_t index = 0; !stoppedFlag.load(std::memory_order_relaxed); index++)
    {
        {
            std::unique_lock<std::mutex> lock{ taskQueueMutex };
            cvTaskDone.wait(lock, [&maxTaskCount]
                {
                    return taskQueue.size() < maxTaskCount;
                });
        }

        auto newTask = std::make_unique<Task>(blockSizeInChar, index);
        readBytes = fread_s(newTask->inputBuffer.get(), blockSizeInChar, sizeof(unsigned char), blockSizeInChar, inputFile.get());
        
        if (!readBytes)
            break;

        {
            std::lock_guard<std::mutex> lock{ taskQueueMutex };
            taskQueue.push(std::move(newTask));
        }

        cvNewTask.notify_one();
    }

    {
        std::lock_guard<std::mutex> lock{ taskQueueMutex };
        taskQueue.push(nullptr);
    }
    cvNewTask.notify_all();
}

void consumer() {
    std::unique_ptr<Task> newTask = nullptr;
    std::unique_ptr<unsigned char[]> md5digest = nullptr;

    while (!stoppedFlag.load(std::memory_order_relaxed))
    {
        {
            std::unique_lock<std::mutex> lock{ taskQueueMutex };
            cvNewTask.wait(lock, []
                {
                    return !taskQueue.empty();
                });

            newTask = std::move(taskQueue.front());
            if (newTask == nullptr)
                break; //do not get nullptr task from queue to stop other consumers
            taskQueue.pop();
        }

        cvTaskDone.notify_one();

        try
        {
            md5digest = MD5Hash::CalsHash(std::move(newTask->inputBuffer), blockSizeInChar);
        }
        catch (MD5Exception& e)
        {
            std::cout << "Got an exception from MD5 calculator: " << e.what() << "\n";
            stoppedFlag.store(true, std::memory_order_relaxed);
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
    //readFromKeyboard();

    if (!OpenFile())
        return -1;


    uint32_t hwConcurency = std::thread::hardware_concurrency();
    uint32_t numThreads = !hwConcurency ? 2 : hwConcurency;

    //change std::thread to async to return error code via futures
    std::thread prod(&producer);
    

    std::vector<std::thread> cons;
    for (uint32_t i = 0; i < numThreads; i++) {
        cons.emplace_back(&consumer);
    }

    prod.join();
    for (uint32_t i = 0; i < numThreads; i++)
        cons[i].join();

    auto qq = hashVector[0].first;

    std::sort(std::execution::par,hashVector.begin(), hashVector.end(), [](auto& left, auto& right) {
        return left.first < right.first; });

    for (uint32_t i = 0; i < hashVector.size(); i++)
    {
        WriteHash(std::move(hashVector[i].second), MD5_DIGEST_LENGTH);
    }

    inputFile.reset();
    outputFile.reset();

    return 0;     
}

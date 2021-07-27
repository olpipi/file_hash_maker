
#include <iostream>
#include <deque>
#include <queue>
#include <mutex>
#include <thread>
#include <execution>
#include <future>
#include "openssl/md5.h"
#define MAX_PATH_LEN 256

char inputFileName[MAX_PATH_LEN] = "input.bin";
char outputFileName[MAX_PATH_LEN] = "output.txt";
uint32_t blockSizeInChar = 1024 * 1024;

std::shared_ptr<FILE> inputFile, outputFile;

void closeFile(FILE* ptr)
{
    fclose(ptr);
};



class MyCustomException : public std::exception
{
public:
    MyCustomException(char const* const _Message) noexcept
        :std::exception(_Message)
    {}
};


class MD5Hash
{
public:
    
    //return size is always == MD5_DIGEST_LENGTH
    static std::unique_ptr<unsigned char[]> CalsHash(std::unique_ptr<unsigned char[]> dataToHash, uint32_t size)
    {
        MD5_CTX md5Ctx{};
        auto md5digest = std::make_unique<unsigned char[]>(MD5_DIGEST_LENGTH);

        if (1 != MD5_Init(&md5Ctx))
            throw MyCustomException("failed to init MD5 hash");

        if (1 != MD5_Update(&md5Ctx, static_cast<const void*>(dataToHash.get()), size))
            throw MyCustomException("failed to put data for MD5");

        if (1 != MD5_Final(md5digest.get(), &md5Ctx))
            throw MyCustomException("failed to get result from MD5");

        return md5digest;
    }
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

void WriteHash(std::unique_ptr<unsigned char[]> pValue, uint32_t size)
{
    if (size != fwrite(pValue.get(), sizeof(unsigned char), size, outputFile.get()))
        throw MyCustomException("cannot write to file");
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
        {
            if (ferror(inputFile.get()))
                throw MyCustomException("cannot read from file");

            break; //EOF
        }
        {
            std::lock_guard<std::mutex> lock{ taskQueueMutex };
            taskQueue.push(std::move(newTask));
        }

        cvNewTask.notify_one();
    }

    {
        //nullptr task to stop consumers
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
        catch (MyCustomException& e)
        {
            stoppedFlag.store(true, std::memory_order_relaxed);
            throw e;
        }

        {
            std::lock_guard<std::mutex> lock(hashVectorMutex);
            hashVector.emplace_back(newTask->index, std::move(md5digest));
        }

    }
}

void readFromKeyboard()
{
    std::cout << "input file: ";
    std::cin >> inputFileName;

    std::cout << "output file: ";
    std::cin >> outputFileName;

    std::cout << "block size in bytes: ";
    std::cin >> blockSizeInChar;
}

int main()
{
    readFromKeyboard();

    if (!OpenFile())
        return -1;


    uint32_t hwConcurency = std::thread::hardware_concurrency();
    uint32_t numThreads = !hwConcurency ? 2 : hwConcurency;

    //launch producer
    auto prodF = std::async(std::launch::async, producer);
    
    //launch consumers
    std::vector<std::future<void>> consF(numThreads);
    for (uint32_t i = 0; i < numThreads; i++) {
        consF[i] = std::async(std::launch::async, consumer);
    }

    bool success = true;
    //wait for threads to finish
    try
    {
        prodF.get();
    }
    catch (MyCustomException& e)
    {
        std::cout << "Got an exception from producer: " << e.what() << "\n";
        success = false;
    }
    for (uint32_t i = 0; i < numThreads; i++)
    {
        try
        {
            consF[i].get();
        }
        catch (MyCustomException& e)
        {
            std::cout << "Got an exception from consumer: " << e.what() << "\n";
            success = false;
        }
    }

    if (success)
    {
        //get results together
        std::sort(std::execution::par, hashVector.begin(), hashVector.end(), [](auto& left, auto& right) {
            return left.first < right.first; });

        for (uint32_t i = 0; i < hashVector.size(); i++)
        {
            try
            {
                WriteHash(std::move(hashVector[i].second), MD5_DIGEST_LENGTH);
            }
            catch (MyCustomException& e)
            {
                std::cout << "Got an exception: " << e.what() << "\n";
                break;
            }
        }
    }

    inputFile.reset();
    outputFile.reset();

    return 0;     
}

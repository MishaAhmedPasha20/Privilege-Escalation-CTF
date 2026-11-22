#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <queue>
#include <semaphore.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/wait.h>
#include <chrono>
#include <iomanip>
#include <atomic>
#include <map>

std::mutex stateMutex;
std::queue<std::string> logQueue;
std::atomic<bool> running{true};
int score = 0;
sem_t execSemaphore;

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

void logWorker() {
    std::ofstream logFile("activity.log", std::ios::app);
    while (running || !logQueue.empty()) {
        std::string entry;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (!logQueue.empty()) {
                entry = logQueue.front();
                logQueue.pop();
            }
        }
        if (!entry.empty()) {
            logFile << entry << std::endl;
            logFile.flush();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

void logEvent(const std::string& msg) {
    std::lock_guard<std::mutex> lock(stateMutex);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%F %T") << " - " << msg;
    logQueue.push(ss.str());
}

// Runs a shell command as a child process using fork/exec, gated by a semaphore
int runEnumCommand(const std::string& cmd) {
    sem_wait(&execSemaphore);
    pid_t pid = fork();
    if (pid == 0) {
        execlp("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        sem_post(&execSemaphore);
        return WEXITSTATUS(status);
    }
    sem_post(&execSemaphore);
    return -1;
}

std::map<int, std::string> loadHashes() {
    std::map<int, std::string> hashes;
    std::ifstream f("flags.hash");
    std::string line;
    while (std::getline(f, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            int id = std::stoi(line.substr(0, pos));
            hashes[id] = line.substr(pos + 1);
        }
    }
    return hashes;
}

int main() {
    sem_init(&execSemaphore, 0, 2); // max 2 concurrent enum commands

    std::thread logThread(logWorker);
    logEvent("Harness started");

    auto flagHashes = loadHashes();
    std::map<int, bool> captured;

    std::cout << "=== PrivEsc CTF Harness ===\n";
    std::cout << "Commands: enum <cmd> | submit <id> <flag> | score | quit\n\n";

    std::string line;
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit") {
            break;
        } else if (cmd == "enum") {
            std::string rest;
            std::getline(iss, rest);
            logEvent("Enumeration run: " + rest);
            runEnumCommand(rest);
        } else if (cmd == "submit") {
            int id; std::string flag;
            iss >> id >> flag;
            if (flagHashes.count(id) && sha256(flag) == flagHashes[id] && !captured[id]) {
                captured[id] = true;
                int pts = (id == 4) ? 25 : 10; // custom binary worth more
                {
                    std::lock_guard<std::mutex> lock(stateMutex);
                    score += pts;
                }
                logEvent("Flag " + std::to_string(id) + " captured (+" + std::to_string(pts) + " pts)");
                std::cout << "Correct! +" << pts << " points.\n";
            } else {
                logEvent("Failed submission attempt for flag " + std::to_string(id));
                std::cout << "Incorrect or already captured.\n";
            }
        } else if (cmd == "score") {
            std::lock_guard<std::mutex> lock(stateMutex);
            std::cout << "Current score: " << score << "/55\n";
        } else {
            std::cout << "Unknown command.\n";
        }
    }

    running = false;
    logEvent("Harness session ended. Final score: " + std::to_string(score));
    logThread.join();
    std::cout << "Final score: " << score << "\n";
    return 0;
}

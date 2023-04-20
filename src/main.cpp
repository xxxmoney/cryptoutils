#include "handlers.h"
#include <iostream>

int main(int argc, const char **argv)
{
    const auto &handlers = GetUtilHandlers();

    if (argc < 2 || handlers.find(argv[1]) == handlers.end())
    {
        std::cout << "utils:\n";
        for (const auto &[utilname, func] : handlers)
            std::cout << utilname << '\n';
        
        return -1;
    }

    return handlers.at(argv[1])(argc - 2, argv + 2);
}


# chmod +x clear_files.sh
# ./clear_files.sh

if [ -d "Admin/homomorphic_keys" ]; then
    rm -r Admin/homomorphic_keys
fi
if [ -d "Admin/root_CA" ]; then
    rm -r Admin/root_CA
fi


if [ -d "Client1/Files" ]; then
    rm -r Client1/Files
fi
if [ -d "Client2/Files" ]; then
    rm -r Client2/Files
fi
if [ -d "Client3/Files" ]; then
    rm -r Client3/Files
fi
if [ -d "Client1/Answers" ]; then
    rm -r Client1/Answers
fi
if [ -d "Client2/Answers" ]; then
    rm -r Client2/Answers
fi
if [ -d "Client3/Answers" ]; then
    rm -r Client3/Answers
fi


if [ -d "Server/Files" ]; then
    rm -r Server/Files
fi
if [ -d "Server/Messages" ]; then
    rm -r Server/Messages
fi
if [ -d "Server/Encrypted_Database" ]; then
    rm -r Server/Encrypted_Database
fi


if [ -f "Admin/admin" ]; then
    rm Admin/admin
fi
if [ -f "Client1/client" ]; then
    rm Client1/client
fi
if [ -f "Client2/client" ]; then
    rm Client2/client
fi
if [ -f "Client3/client" ]; then
    rm Client3/client
fi
if [ -f "Server/server" ]; then
    rm Server/server
fi


if [ -d "Admin/CMakeFiles" ]; then
    rm -r Admin/CMakeFiles
fi
if [ -d "Client1/CMakeFiles" ]; then
    rm -r Client1/CMakeFiles
fi
if [ -d "Client2/CMakeFiles" ]; then
    rm -r Client2/CMakeFiles
fi
if [ -d "Client3/CMakeFiles" ]; then
    rm -r Client3/CMakeFiles
fi
if [ -d "Server/CMakeFiles" ]; then
    rm -r Server/CMakeFiles
fi


if [ -f "Admin/cmake_install.cmake" ]; then
    rm Admin/cmake_install.cmake
fi
if [ -f "Client1/cmake_install.cmake" ]; then
    rm Client1/cmake_install.cmake
fi
if [ -f "Client2/cmake_install.cmake" ]; then
    rm Client2/cmake_install.cmake
fi
if [ -f "Client3/cmake_install.cmake" ]; then
    rm Client3/cmake_install.cmake
fi
if [ -f "Server/cmake_install.cmake" ]; then
    rm Server/cmake_install.cmake
fi


if [ -f "Client1/session.key" ]; then
    rm Client1/session.key
fi
if [ -f "Client2/session.key" ]; then
    rm Client2/session.key
fi
if [ -f "Client3/session.key" ]; then
    rm Client3/session.key
fi
if [ -f "Server/session.key" ]; then
    rm Server/session.key
fi


if [ -f "Admin/CMakeCache.txt" ]; then
    rm Admin/CMakeCache.txt
fi
if [ -f "Client1/CMakeCache.txt" ]; then
    rm Client1/CMakeCache.txt
fi
if [ -f "Client2/CMakeCache.txt" ]; then
    rm Client2/CMakeCache.txt
fi
if [ -f "Client3/CMakeCache.txt" ]; then
    rm Client3/CMakeCache.txt
fi
if [ -f "Server/CMakeCache.txt" ]; then
    rm Server/CMakeCache.txt
fi


if [ -f "Admin/Makefile" ]; then
    rm Admin/Makefile
fi
if [ -f "Client1/Makefile" ]; then
    rm Client1/Makefile
fi
if [ -f "Client2/Makefile" ]; then
    rm Client2/Makefile
fi
if [ -f "Client3/Makefile" ]; then
    rm Client3/Makefile
fi
if [ -f "Server/Makefile" ]; then
    rm Server/Makefile
fi








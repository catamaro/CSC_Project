# chmod +x clear_files.sh
# ./clear_files.sh

rm -r Admin/homomorphic_keys
rm -r Admin/root_CA

rm -r Client1/Files
rm -r Client2/Files
rm -r Client1/Answers
rm -r Client2/Answers

rm -r Server/Files
rm -r Server/Messages
rm -r Server/Encrypted_Database

rm Admin/admin
rm Client1/client
rm Client2/client
rm Server/server

rm -r Admin/CMakeFiles
rm -r Client1/CMakeFiles
rm -r Client2/CMakeFiles
rm -r Server/CMakeFiles

rm Admin/cmake_install.cmake
rm Client1/cmake_install.cmake
rm Client2/cmake_install.cmake
rm Server/cmake_install.cmake

rm Admin/CMakeCache.txt
rm Client1/CMakeCache.txt
rm Client2/CMakeCache.txt
rm Server/CMakeCache.txt

rm Admin/cmake_install.cmake
rm Client1/cmake_install.cmake
rm Client2/cmake_install.cmake
rm Server/cmake_install.cmake

rm Admin/Makefile
rm Client1/Makefile
rm Client2/Makefile
rm Server/Makefile




# CMAKE VERSION_
cmake_minimum_required(VERSION 3.12) 

# PROJECT NAME [OPTIONAL]:
project(EXAMPLE)

# FIND SEAL VERSION:
find_package(SEAL 3.6.0 EXACT REQUIRED)


# TO SET DIFERENT DIRECTORY (e.g. yourdir) [OPTIONAL, BY DEFAULT: PROJECT DIRECTORY]:
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY)

# CHOOSE EXECUTABLE NAME (e.g exec)
add_executable(admin)

# ADD ALL SOURCE FILES TO BE COMPILED (e.g. exec.cpp)
target_sources(admin PRIVATE admin.cpp )

# PRIVATE FLAG MAY BE CHANGED FOR PUBLIC OR INTERFACE
# SEE: https://cmake.org/pipermail/cmake/2016-May/063400.html


# LINK SEAL
target_link_libraries(admin SEAL::seal)

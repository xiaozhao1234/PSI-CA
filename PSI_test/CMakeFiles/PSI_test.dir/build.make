# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/yyc/桌面/clion/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/yyc/桌面/clion/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yyc/桌面/test2222/OPRF-PSI

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yyc/桌面/test2222/OPRF-PSI

# Include any dependencies generated for this target.
include PSI_test/CMakeFiles/PSI_test.dir/depend.make

# Include the progress variables for this target.
include PSI_test/CMakeFiles/PSI_test.dir/progress.make

# Include the compile flags for this target's objects.
include PSI_test/CMakeFiles/PSI_test.dir/flags.make

PSI_test/CMakeFiles/PSI_test.dir/main.cpp.o: PSI_test/CMakeFiles/PSI_test.dir/flags.make
PSI_test/CMakeFiles/PSI_test.dir/main.cpp.o: PSI_test/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yyc/桌面/test2222/OPRF-PSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object PSI_test/CMakeFiles/PSI_test.dir/main.cpp.o"
	cd /home/yyc/桌面/test2222/OPRF-PSI/PSI_test && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/PSI_test.dir/main.cpp.o -c /home/yyc/桌面/test2222/OPRF-PSI/PSI_test/main.cpp

PSI_test/CMakeFiles/PSI_test.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PSI_test.dir/main.cpp.i"
	cd /home/yyc/桌面/test2222/OPRF-PSI/PSI_test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yyc/桌面/test2222/OPRF-PSI/PSI_test/main.cpp > CMakeFiles/PSI_test.dir/main.cpp.i

PSI_test/CMakeFiles/PSI_test.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PSI_test.dir/main.cpp.s"
	cd /home/yyc/桌面/test2222/OPRF-PSI/PSI_test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yyc/桌面/test2222/OPRF-PSI/PSI_test/main.cpp -o CMakeFiles/PSI_test.dir/main.cpp.s

# Object files for target PSI_test
PSI_test_OBJECTS = \
"CMakeFiles/PSI_test.dir/main.cpp.o"

# External object files for target PSI_test
PSI_test_EXTERNAL_OBJECTS =

bin/PSI_test: PSI_test/CMakeFiles/PSI_test.dir/main.cpp.o
bin/PSI_test: PSI_test/CMakeFiles/PSI_test.dir/build.make
bin/PSI_test: lib/libPSI.a
bin/PSI_test: /home/yyc/桌面/test2222/libOTe/lib/liblibOTe.a
bin/PSI_test: /home/yyc/桌面/test2222/libOTe/lib/libcryptoTools.a
bin/PSI_test: /home/yyc/桌面/test2222/libOTe/cryptoTools/thirdparty/linux/miracl/miracl/source/libmiracl.a
bin/PSI_test: /home/yyc/桌面/test2222/libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_system.a
bin/PSI_test: /home/yyc/桌面/test2222/libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_thread.a
bin/PSI_test: PSI_test/CMakeFiles/PSI_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yyc/桌面/test2222/OPRF-PSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../bin/PSI_test"
	cd /home/yyc/桌面/test2222/OPRF-PSI/PSI_test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/PSI_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
PSI_test/CMakeFiles/PSI_test.dir/build: bin/PSI_test

.PHONY : PSI_test/CMakeFiles/PSI_test.dir/build

PSI_test/CMakeFiles/PSI_test.dir/clean:
	cd /home/yyc/桌面/test2222/OPRF-PSI/PSI_test && $(CMAKE_COMMAND) -P CMakeFiles/PSI_test.dir/cmake_clean.cmake
.PHONY : PSI_test/CMakeFiles/PSI_test.dir/clean

PSI_test/CMakeFiles/PSI_test.dir/depend:
	cd /home/yyc/桌面/test2222/OPRF-PSI && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yyc/桌面/test2222/OPRF-PSI /home/yyc/桌面/test2222/OPRF-PSI/PSI_test /home/yyc/桌面/test2222/OPRF-PSI /home/yyc/桌面/test2222/OPRF-PSI/PSI_test /home/yyc/桌面/test2222/OPRF-PSI/PSI_test/CMakeFiles/PSI_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : PSI_test/CMakeFiles/PSI_test.dir/depend


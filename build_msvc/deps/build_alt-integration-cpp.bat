cd alt-integration-cpp
rmdir build /S /Q
mkdir build 
git submodule update --init
cmake -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake -B build -A x64 -DSHARED=OFF -DTESTING=OFF .
cd build
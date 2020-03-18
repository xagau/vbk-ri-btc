cd alt-integration-cpp
rmdir build /S /Q
mkdir build 
git submodule update --init
cmake -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake -B build -A x64 SHARED=OFF TESTING=OFF .
cd build
msbuild altintegration.sln
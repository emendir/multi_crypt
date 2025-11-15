sudo apt update && sudo apt install build-essential python3-dev cmake libssl-dev
# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib
# export OQS_INSTALL_PATH=/path/to/liboqs
cd $(mktemp -d)
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
# if [ -e liboqs/build ];then
#   rm -rf liboqs/build
# fi
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
# cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX="C:\liboqs" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
sudo cmake --build liboqs/build --target install

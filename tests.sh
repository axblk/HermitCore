#!/bin/bash

OS_NAME=$1
OS_VERSION=$2

if [ "$OS_NAME" = "centos" ]; then

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

# First, install all the needed packages.
yum install -y wget gettext flex bison binutils gcc gcc-c++ texinfo kernel-headers rpm-build kernel-devel boost-devel cmake git tar gzip make autotools

wget http://checkinstall.izto.org/files/source/checkinstall-1.6.2.tar.gz
tar xzvf checkinstall-1.6.2.tar.gz
cd checkinstall-1.6.2
./configure
make
make install
cd ..
rm -rf checkinstall*

mkdir -p build
cd build
../configure --target=x86_64-hermit --prefix=/opt/hermit --disable-shared --disable-nls --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-libssp --enable-tls --disable-multilib
make
checkinstall -R -y --exclude=build --pkggroup=main --maintainer=stefan@eonerc.rwth-aachen.de --pkgsource=https://hermitcore.org --pkgname=newlib-hermit --pkgversion=2.30.51 --pkglicense=GPL2 make install

else

export DEBIAN_FRONTEND="noninteractive"

apt-get -qq update
apt-get install -y qemu-system-x86 cmake wget curl gnupg checkinstall gawk dialog apt-utils flex bison binutils texinfo gcc g++ libmpfr-dev libmpc-dev libgmp-dev libisl-dev packaging-dev build-essential libtool autotools-dev autoconf pkg-config apt-transport-https nasm

echo "deb [trusted=yes] https://dl.bintray.com/hermitcore/ubuntu bionic main" | tee -a /etc/apt/sources.list
apt-get update
apt-get install -y --allow-unauthenticated binutils-hermit libhermit newlib-hermit pte-hermit gcc-hermit #gcc-hermit-bootstrap
export PATH=/opt/hermit/bin:$PATH

mkdir -p build
cd build
#cmake -DTOOLCHAIN_BIN_DIR=/opt/hermit/bin -DCMAKE_INSTALL_PREFIX=/opt/hermit .. #-DBOOTSTRAP=true ..
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=true ..
install -m 644 usr/libomp/libgomp.spec /opt/hermit/x86_64-hermit/lib
make -j1 package

cd ..
mkdir -p tmp
dpkg-deb -R build/libhermit_0.2.8-1_amd64.deb tmp
rm -f build/libhermit_0.2.8-1_amd64.deb

fi

TDIR=/work/build/opt/hermit/x86_64-hermit/extra
FILES="$TDIR/tests/hello $TDIR/tests/hellof $TDIR/tests/hello++ $TDIR/tests/thr_hello $TDIR/tests/pi $TDIR/benchmarks/stream $TDIR/benchmarks/basic $TDIR/tests/signals $TDIR/tests/test-malloc $TDIR/tests/test-malloc-mt $TDIR/tests/argv_envp"
PROXY=/work/build/opt/hermit/bin/proxy

for f in $FILES; do echo "check $f..."; HERMIT_ISLE=qemu HERMIT_CPUS=1 HERMIT_KVM=0 HERMIT_VERBOSE=1 timeout --kill-after=5m 5m $PROXY $f || exit 1; done

for f in $FILES; do echo "check $f..."; HERMIT_ISLE=qemu HERMIT_CPUS=2 HERMIT_KVM=0 HERMIT_VERBOSE=1 timeout --kill-after=5m 5m $PROXY $f || exit 1; done

# test echo server at port 8000
HERMIT_ISLE=qemu HERMIT_CPUS=1 HERMIT_KVM=0 HERMIT_VERBOSE=1 HERMIT_APP_PORT=8000 $PROXY $TDIR/tests/server &
sleep 10
curl http://127.0.0.1:8000/help
sleep 1
curl http://127.0.0.1:8000/hello
sleep 1

# kill server
kill $!

# test connection via netio
#wget http://web.ars.de/wp-content/uploads/2017/04/netio132.zip
#unzip netio132.zip
#HERMIT_ISLE=qemu HERMIT_CPUS=2 HERMIT_KVM=0 HERMIT_VERBOSE=1 HERMIT_APP_PORT=18767 $PROXY $TDIR/benchmarks/netio &
#sleep 1
#chmod a+rx bin/linux-x86_64
#bin/linux-x86_64 -t -b 4k localhost
#sleep 1

# kill server
#kill $!

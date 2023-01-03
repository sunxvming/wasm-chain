#!/bin/sh

TARDIR=/data

echo "make dir ${TARDIR}"
mkdir ${TARDIR}
cp llvm-6.0.0.src.tar.xz ${TARDIR}
cd ${TARDIR}
xz -d llvm-6.0.0.src.tar.xz
tar -xvf llvm-6.0.0.src.tar

cd llvm-6.0.0.src
mkdir build
cd build

cmake3 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ..
make -j4
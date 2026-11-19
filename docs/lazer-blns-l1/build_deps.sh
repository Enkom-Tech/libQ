#!/bin/sh
# Build m4, GMP and MPFR from source, for hosts that lack m4, gmp.h and mpfr.h.
# Usage: WORK=<scratch dir> sh build_deps.sh      (default WORK is ./deps-work; use a fresh directory)
set -e
WORK=${WORK:-$PWD/deps-work}
mkdir -p "$WORK"
cd "$WORK"
P=$WORK/deps
export PATH=$P/bin:$PATH
curl -sSL -o m4.tar.xz https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz
curl -sSL -o gmp.tar.xz https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
curl -sSL -o mpfr.tar.xz https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.2.tar.xz
mkdir -p src-m4 src-mpfr gmp-build
tar -xf m4.tar.xz -C src-m4
tar -xf gmp.tar.xz -C gmp-build
(cd src-m4/m4-1.4.19 && ./configure --prefix=$P -q && make -j2 && make install) > m4.log 2>&1
echo m4 done
(cd gmp-build/gmp-6.3.0 && ./configure --prefix=$P --disable-shared --with-pic -q && make -j2 && make install) > gmp-build.log 2>&1
echo gmp done
tar -xf mpfr.tar.xz -C src-mpfr
(cd src-mpfr/mpfr-4.2.2 && ./configure --prefix=$P --disable-shared --with-pic --with-gmp=$P -q && make -j2 && make install) > mpfr-build.log 2>&1
echo mpfr done

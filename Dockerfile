FROM debian:bullseye

RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install --no-install-recommends -o APT::Immediate-Configure=false -y \
      upx cmake gcc-multilib make libsdl2-dev:i386 \
 && rm -rf /var/lib/apt/lists/*

COPY . /h7shim
WORKDIR /h7shim
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make

WORKDIR /h7shim/build
CMD /h7shim/build/h7shim

# To run this Dockerfile in a pretty standard Linux setup, run:
#   xhost +local:root
#   docker build . -th7shim
#   docker run -it --device /dev/snd -e "ALSA_CARD=Generic" -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix h7shim
FROM i386/alpine:3.12

RUN apk add cmake gcc make musl-dev \
            ca-certificates curl unzip \
            alpine-sdk sudo \
            xorg-server alsa-lib

# Instead of installing sdl2 from the repositories, build it from sources
# without OpenGL support (this sucks and will probably break sooner or later)
# The problem is that getting hardware acceleration to work inside Docker is a
# pain, and apparently there's no other way to force SDL to fall back to
# non-accelerated rendering other than recompiling it with it disabled
RUN adduser -S builduser -G abuild \
 && echo "builduser ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers \
 && chgrp abuild /var/cache/distfiles \
 && chmod g+w /var/cache/distfiles

USER builduser
WORKDIR /home/builduser
RUN git clone https://github.com/alpinelinux/aports --depth 1 --branch 3.12-stable --single-branch \
 && cd aports/community/sdl2 \
 && sed -i APKBUILD -e 's/-DVIDEO_WAYLAND=ON/-DVIDEO_WAYLAND=OFF -DVIDEO_KMSDRM=OFF -DVIDEO_OPENGL=OFF -DVIDEO_OPENGLES=OFF/g' \
 && abuild-keygen -a -i \
 && abuild -r \
 && sudo apk add --allow-untrusted "/home/builduser/packages/community/x86/sdl2-"*
USER root

# Now build our actual code
WORKDIR /h7shim/
COPY  --chown=builduser:root ./download_HEAVEN7W.sh ./
RUN ./download_HEAVEN7W.sh

COPY CMakeLists.txt winapi2sdl.c winapi2sdl.h h7shim.c ./
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make
CMD /h7shim/build/h7shim

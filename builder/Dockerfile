FROM ubuntu:22.04

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sudo \
    vim \
    apt-transport-https \
    autoconf2.13 \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    glib-2.0-dev \
    libglu1-mesa-dev \
    libgtk-3-dev \
    libpulse-dev \
    libtool \
    p7zip-full \
    subversion \
    gzip \
    libasound2-dev \
    libatspi2.0-dev \
    libcups2-dev \
    libdbus-1-dev \
    libicu-dev \
    libglu1-mesa-dev \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    libx11-xcb-dev \
    libxcb* \
    libxi-dev \
    libxrender-dev \
    libxss1 \
    libncurses5
RUN ln -s /usr/bin/python3 /usr/bin/python 
RUN curl -sL https://deb.nodesource.com/setup_16.x | bash -

# Stuff that have to be installed and modified "manually"
RUN apt-get -y install nodejs clang-15 lld-15 wget sudo x11-utils apt-utils && \
mv -v /usr/bin/clang-15 /usr/bin/clang && \
mv -v /usr/bin/clang-cpp-15 /usr/bin/clang-cpp && \
mv -v /usr/bin/clang++-15 /usr/bin/clang++ && \
mv -v /usr/bin/dsymutil-15 /usr/bin/dsymutil && \
mv -v /usr/bin/llc-15 /usr/bin/llc && \
mv -v /usr/bin/lli-15 /usr/bin/lli && \
mv -v /usr/bin/lli-child-target-15 /usr/bin/lli-child-target && \
mv -v /usr/bin/llvm-PerfectShuffle-15 /usr/bin/llvm-PerfectShuffle && \
mv -v /usr/bin/llvm-addr2line-15 /usr/bin/llvm-addr2line && \
mv -v /usr/bin/llvm-ar-15 /usr/bin/llvm-ar && \
mv -v /usr/bin/llvm-as-15 /usr/bin/llvm-as && \
mv -v /usr/bin/llvm-bcanalyzer-15 /usr/bin/llvm-bcanalyzer && \
mv -v /usr/bin/llvm-c-test-15 /usr/bin/llvm-c-test && \
mv -v /usr/bin/llvm-cat-15 /usr/bin/llvm-cat && \
mv -v /usr/bin/llvm-cfi-verify-15 /usr/bin/llvm-cfi-verify && \
mv -v /usr/bin/llvm-config-15 /usr/bin/llvm-config && \
mv -v /usr/bin/llvm-cov-15 /usr/bin/llvm-cov && \
mv -v /usr/bin/llvm-cvtres-15 /usr/bin/llvm-cvtres && \
mv -v /usr/bin/llvm-cxxdump-15 /usr/bin/llvm-cxxdump && \
mv -v /usr/bin/llvm-cxxfilt-15 /usr/bin/llvm-cxxfilt && \
mv -v /usr/bin/llvm-cxxmap-15 /usr/bin/llvm-cxxmap && \
mv -v /usr/bin/llvm-diff-15 /usr/bin/llvm-diff && \
mv -v /usr/bin/llvm-dis-15 /usr/bin/llvm-dis && \
mv -v /usr/bin/llvm-dlltool-15 /usr/bin/llvm-dlltool && \
mv -v /usr/bin/llvm-dwarfdump-15 /usr/bin/llvm-dwarfdump && \
mv -v /usr/bin/llvm-dwp-15 /usr/bin/llvm-dwp && \
#mv -v /usr/bin/llvm-elfabi-15 /usr/bin/llvm-elfabi && \
mv -v /usr/bin/llvm-exegesis-15 /usr/bin/llvm-exegesis && \
mv -v /usr/bin/llvm-extract-15 /usr/bin/llvm-extract && \
mv -v /usr/bin/llvm-ifs-15 /usr/bin/llvm-ifs && \
mv -v /usr/bin/llvm-install-name-tool-15 /usr/bin/llvm-install-name-tool && \
mv -v /usr/bin/llvm-jitlink-15 /usr/bin/llvm-jitlink && \
mv -v /usr/bin/llvm-lib-15 /usr/bin/llvm-lib && \
mv -v /usr/bin/llvm-link-15 /usr/bin/llvm-link && \
mv -v /usr/bin/llvm-lipo-15 /usr/bin/llvm-lipo && \
mv -v /usr/bin/llvm-lto-15 /usr/bin/llvm-lto && \
mv -v /usr/bin/llvm-lto2-15 /usr/bin/llvm-lto2 && \
mv -v /usr/bin/llvm-mc-15 /usr/bin/llvm-mc && \
mv -v /usr/bin/llvm-mca-15 /usr/bin/llvm-mca && \
mv -v /usr/bin/llvm-modextract-15 /usr/bin/llvm-modextract && \
mv -v /usr/bin/llvm-mt-15 /usr/bin/llvm-mt && \
mv -v /usr/bin/llvm-nm-15 /usr/bin/llvm-nm && \
mv -v /usr/bin/llvm-objcopy-15 /usr/bin/llvm-objcopy && \
mv -v /usr/bin/llvm-objdump-15 /usr/bin/llvm-objdump && \
mv -v /usr/bin/llvm-opt-report-15 /usr/bin/llvm-opt-report && \
mv -v /usr/bin/llvm-pdbutil-15 /usr/bin/llvm-pdbutil && \
mv -v /usr/bin/llvm-profdata-15 /usr/bin/llvm-profdata && \
mv -v /usr/bin/llvm-ranlib-15 /usr/bin/llvm-ranlib && \
mv -v /usr/bin/llvm-rc-15 /usr/bin/llvm-rc && \
mv -v /usr/bin/llvm-readelf-15 /usr/bin/llvm-readelf && \
mv -v /usr/bin/llvm-readobj-15 /usr/bin/llvm-readobj && \
mv -v /usr/bin/llvm-reduce-15 /usr/bin/llvm-reduce && \
mv -v /usr/bin/llvm-rtdyld-15 /usr/bin/llvm-rtdyld && \
mv -v /usr/bin/llvm-size-15 /usr/bin/llvm-size && \
mv -v /usr/bin/llvm-split-15 /usr/bin/llvm-split && \
mv -v /usr/bin/llvm-stress-15 /usr/bin/llvm-stress && \
mv -v /usr/bin/llvm-strings-15 /usr/bin/llvm-strings && \
mv -v /usr/bin/llvm-strip-15 /usr/bin/llvm-strip && \
mv -v /usr/bin/llvm-symbolizer-15 /usr/bin/llvm-symbolizer && \
mv -v /usr/bin/llvm-tblgen-15 /usr/bin/llvm-tblgen && \
mv -v /usr/bin/llvm-undname-15 /usr/bin/llvm-undname && \
mv -v /usr/bin/llvm-xray-15 /usr/bin/llvm-xray && \
mv -v /usr/bin/not-15 /usr/bin/not && \
mv -v /usr/bin/obj2yaml-15 /usr/bin/obj2yaml && \
mv -v /usr/bin/opt-15 /usr/bin/opt && \
mv -v /usr/bin/sanstats-15 /usr/bin/sanstats && \
mv -v /usr/bin/verify-uselistorder-15 /usr/bin/verify-uselistorder && \
mv -v /usr/bin/yaml-bench-15 /usr/bin/yaml-bench && \
mv -v /usr/bin/yaml2obj-15 /usr/bin/yaml2obj && \
mv -v /usr/bin/ld.lld-15 /usr/bin/ld.lld && \
mv -v /usr/bin/lld-15 /usr/bin/lld && \
mv -v /usr/bin/ld64.lld-15 /usr/bin/ld64.lld && \
mv -v /usr/bin/lld-link-15 /usr/bin/lld-link

RUN /bin/bash

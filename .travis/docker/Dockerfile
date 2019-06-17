# {docker build -t insomniacslk/dublin-traceroute -f Dockerfile .}
FROM debian:stable

# Install dependencies
RUN apt-get update &&                          \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        build-essential \
        pkg-config \
        cmake \
        libjsoncpp-dev \
        libtins-dev \
        libpcap-dev \
        `# dependencies for the python module` \
        python3-dev \
        python3-setuptools \
        libgraphviz-dev \
        python3-pygraphviz \
        python3-tabulate \
        && \
    rm -rf /var/lib/apt/lists/*

RUN set -x; \
    git clone https://github.com/insomniacslk/dublin-traceroute.git && \
    cd dublin-traceroute && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make && \
    make install && \
    ldconfig

# also install the python module
RUN set -x; \
    git clone https://github.com/insomniacslk/python-dublin-traceroute.git && \
    cd python-dublin-traceroute && \
    python3 setup.py build && \
    python3 setup.py install

CMD dublin-traceroute 8.8.8.8 && \
    python3 -m dublintraceroute plot trace.json && \
    mv trace.json.png /output/

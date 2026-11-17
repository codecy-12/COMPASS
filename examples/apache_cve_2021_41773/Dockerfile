FROM postgres:latest

ARG HTTPD_VERSION=2.4.49
ARG PCRE_VERSION=8.45

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2-dev \
        binutils \
        build-essential \
        ca-certificates \
        curl \
        libapr1-dev \
        libaprutil1-dev \
        libexpat1-dev \
        perl \
        procps \
        python3 \
        strace \
        uftrace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSLO https://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.gz \
    && curl -fsSLO https://ftp.exim.org/pub/pub/pcre/pcre-${PCRE_VERSION}.tar.gz \
    && tar -xzf httpd-${HTTPD_VERSION}.tar.gz \
    && tar -xzf pcre-${PCRE_VERSION}.tar.gz

RUN cd /src/pcre-${PCRE_VERSION} \
    && ./configure --prefix=/opt/pcre \
    && make -j2 \
    && make install

COPY examples/apache_cve_2021_41773/httpd.conf /tmp/httpd.conf
COPY examples/apache_cve_2021_41773/entrypoint.sh /entrypoint.sh

RUN cd /src/httpd-${HTTPD_VERSION} \
    && ./configure \
        --prefix=/opt/httpd \
        --with-apr=/usr/bin/apr-1-config \
        --with-apr-util=/usr/bin/apu-1-config \
        --with-pcre=/opt/pcre/bin/pcre-config \
        --enable-mods-static='alias authz_core dir log_config mime unixd' \
        --disable-lua \
    && sed -i 's/-Werror//g' Makefile modules/*/Makefile support/Makefile || true \
    && make -j2 \
    && make install

RUN mkdir -p /opt/httpd/htdocs /traces \
    && printf 'apache-41773\n' > /opt/httpd/htdocs/index.html \
    && chmod +x /entrypoint.sh \
    && cp /tmp/httpd.conf /opt/httpd/conf/httpd.conf

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]

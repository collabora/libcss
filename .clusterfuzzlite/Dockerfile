FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y python3-pip ninja-build
RUN pip3 install meson

# Copy your entire local libcss repo (with branch changes) into the container
COPY . $SRC/libcss

# Set working dir
WORKDIR $SRC/libcss

# Copy build.sh to $SRC/ (adjust if build.sh needs to be elsewhere)
COPY .clusterfuzzlite/build.sh $SRC/



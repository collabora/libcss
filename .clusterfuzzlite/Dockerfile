# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y python3-pip ninja-build
RUN pip3 install meson

# Copy your entire local libcss repo (with branch changes) into the container
COPY . $SRC/libcss

# Clone libcss-tests only if it's not already in your local repo (remove this line if you have it locally)
RUN git clone --depth 1 https://gitlab.collabora.com/libcss/libcss-tests.git $SRC/libcss-tests

# Set working dir
WORKDIR $SRC/libcss

# Copy build.sh to $SRC/ (adjust if build.sh needs to be elsewhere)
COPY .clusterfuzzlite/build.sh $SRC/



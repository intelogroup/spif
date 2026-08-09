FROM gcr.io/oss-fuzz-base/base-builder-python
RUN git clone --depth 1 https://github.com/intelogroup/spif.git spif
COPY build.sh $SRC/
COPY fuzz_targets/*.py $SRC/
WORKDIR spif/spif

TRACY_PATH=<path-to-tracy>
CUDA_TOOLKIT_PATH=/usr/local/cuda
CUDA_CUPTI_PATH=${CUDA_TOOLKIT_PATH}/extras/CUPTI

# pass -v to nvcc for verbose build information
nvcc -O2 -std=c++17 cuda-graph-demo.cu \
     -o cuda-graph-demo \
     -I "${TRACY_PATH}/public" \
     -I "${CUDA_CUPTI_PATH}/include" -I "${CUDA_TOOLKIT_PATH}/include" \
     -L "${CUDA_CUPTI_PATH}/lib64"   -L "${CUDA_TOOLKIT_PATH}/lib64" \
     -lcupti -lcuda

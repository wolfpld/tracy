# profiler/cmake/GenerateGitRef.cmake
# This script is run at BUILD TIME via `cmake -P`

# Inputs (passed via -D)
#   GIT_COMMIT_HASH
#   INPUT_FILE
#   OUTPUT_FILE

configure_file("${INPUT_FILE}" "${OUTPUT_FILE}" @ONLY)

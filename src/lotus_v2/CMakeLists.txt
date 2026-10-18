add_library(lotus_v2_mdbx STATIC
    vendor/libmdbx/mdbx.c
    vendor/libmdbx/mdbx_batch.c
)
set_target_properties(lotus_v2_mdbx PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
target_include_directories(lotus_v2_mdbx PUBLIC vendor/libmdbx)
target_compile_definitions(lotus_v2_mdbx PUBLIC MDBX_BUILD_SHARED_LIBRARY=0 PRIVATE NDEBUG MDBX_BUILD_FLAGS="-O3 -DNDEBUG" MDBX_WITHOUT_MSVC_CRT=0)
target_compile_options(lotus_v2_mdbx PRIVATE -O3 -Wno-unused-parameter -Wno-sign-compare -Wno-cast-align -Wno-gnu -Wno-shadow -Wno-documentation -Wno-implicit-fallthrough)

# Compile the commitment primitives at their own introduction, before overlay
# callers are added. Later foundation sources extend this target.
add_library(lotus_v2_header STATIC tagged_hash.cpp)
target_include_directories(lotus_v2_header PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" ..)
target_link_libraries(lotus_v2_header PUBLIC crypto)

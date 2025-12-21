# Bazel build file for OpenFHE library
# Uses rules_foreign_cc to build OpenFHE with its native CMake build system

load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")
load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

# Build all OpenFHE source files
filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

# Build OpenFHE using CMake
cmake(
    name = "openfhe_cmake",
    lib_source = ":all_srcs",
    out_static_libs = [
        "libOPENFHEcore_static.a",
        "libOPENFHEpke_static.a",
    ],
    out_include_dir = "include/openfhe",
    deps = ["@cereal//:cereal"],
    cache_entries = {
        "CMAKE_BUILD_TYPE": "Release",
        "BUILD_UNITTESTS": "OFF",
        "BUILD_EXAMPLES": "OFF",
        "BUILD_BENCHMARKS": "OFF",
        "BUILD_EXTRAS": "OFF",
        "BUILD_SHARED": "OFF",
        "BUILD_STATIC": "ON",
        "WITH_BE2": "OFF",
        "WITH_BE4": "ON",  # NTL backend
        "WITH_OPENMP": "OFF",
        "MATHBACKEND": "4",
        "WITH_TCM": "OFF",
        "GIT_SUBMOD_AUTO": "OFF",  # Disable git submodule auto-download
        # Enable C++ exceptions and disable strict warnings, add cereal include path
        "CMAKE_CXX_FLAGS": "-fexceptions -Wno-unused-parameter -Wno-error -Wno-missing-field-initializers -I$$EXT_BUILD_DEPS$$/include",
    },
    targets = [
        "OPENFHEcore_static",
        "OPENFHEpke_static",
    ],
    generate_crosstool_file = True,
    # Custom build and install - skip cmake install entirely
    build_args = ["-j8"],
    install = False,
    # Copy libs and headers manually - preserve directory structure
    postfix_script = """
        set -e
        mkdir -p $$INSTALLDIR$$/lib
        cp lib/libOPENFHEcore_static.a $$INSTALLDIR$$/lib/
        cp lib/libOPENFHEpke_static.a $$INSTALLDIR$$/lib/
        
        # Create include structure - preserve subdirectories from src/core/include
        mkdir -p $$INSTALLDIR$$/include/openfhe
        cp -r $$EXT_BUILD_ROOT$$/external/+_repo_rules+openfhe/src/core/include/* $$INSTALLDIR$$/include/openfhe/
        cp -r $$EXT_BUILD_ROOT$$/external/+_repo_rules+openfhe/src/pke/include/* $$INSTALLDIR$$/include/openfhe/
        cp -r $$EXT_BUILD_ROOT$$/external/+_repo_rules+openfhe/src/binfhe/include/* $$INSTALLDIR$$/include/openfhe/
        
        # Copy generated config file (from build dir)
        cp src/core/config_core.h $$INSTALLDIR$$/include/openfhe/
    """,
)

# Convenience wrapper for OpenFHE PKE
cc_library(
    name = "openfhe_pke",
    deps = [":openfhe_cmake"],
)

# Alias for main library
alias(
    name = "openfhe",
    actual = ":openfhe_pke",
)

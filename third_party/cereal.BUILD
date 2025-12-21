# Bazel build file for cereal serialization library
load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "cereal",
    hdrs = glob([
        "include/cereal/**/*.hpp",
        "include/cereal/**/*.h",
    ]),
    includes = ["include"],
)

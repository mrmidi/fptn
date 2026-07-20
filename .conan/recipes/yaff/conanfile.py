import os

from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import get, replace_in_file


class YaffConan(ConanFile):
    name = "yaff"
    version = "0.0.0"

    settings = "os", "arch", "compiler", "build_type"
    generators = ("CMakeDeps",)

    requires = ("protobuf/5.29.3",)

    default_options = {
        "protobuf/*:lite": True,
        "protobuf/*:upb": False,
        "protobuf/*:with_rtti": False,
        "protobuf/*:with_zlib": False,
        "protobuf/*:debug_suffix": False,
    }

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("protobuf/5.29.3")

    def source(self):
        # PR0: pin YAFF to a specific commit for reproducible builds.
        # The replace_in_file patches below are tested against this exact
        # source; a moving main branch could silently break them.
        _yaff_commit = "d6f74675374b587ce24112c284abd54a92090221"
        _yaff_sha256 = "904f06b460c82e60b0303a73c7f53f2735c795adb7de8e5d1327fb0ac2987576"
        get(
            self,
            f"https://github.com/yandex/yaff/archive/{_yaff_commit}.tar.gz",
            sha256=_yaff_sha256,
            strip_root=True,
        )
        replace_in_file(
            self,
            os.path.join(self.source_folder, "src", "protoc-plugin", "CMakeLists.txt"),
            "install(TARGETS yaff_protoc_plugin\n    EXPORT YaFFTargets\n",
            "install(TARGETS yaff_protoc_plugin\n",
        )
        # MSVC only forward-declares std::ostream via <string_view>, so the
        # operator<< in array.h fails with an incomplete type. Pull in <ostream>.
        replace_in_file(
            self,
            os.path.join(self.source_folder, "include", "yaff", "array.h"),
            "#include <string_view>",
            "#include <ostream>\n#include <string_view>",
        )
        # C++23: libc++ ranges probes .begin() eagerly via the
        # input_or_output_iterator concept, which instantiates
        # ArrayIterator<T> before its definition (line ~347). Defer
        # begin()/end() to out-of-line definitions after ArrayIterator.
        replace_in_file(
            self,
            os.path.join(self.source_folder, "include", "yaff", "array.h"),
            "    auto begin() const noexcept {\n"
            "        return typename T::const_iterator(*static_cast<const T*>(this), 0);\n"
            "    }\n"
            "\n"
            "    auto end() const noexcept {\n"
            "        return typename T::const_iterator(*static_cast<const T*>(this), Size_);\n"
            "    }",
            "    auto begin() const noexcept;\n"
            "    auto end() const noexcept;",
        )
        replace_in_file(
            self,
            os.path.join(self.source_folder, "include", "yaff", "array.h"),
            "class ArrayIterator : public BaseArrayIterator<T, ArrayIterator<T>> {\n"
            "    using Base = BaseArrayIterator<T, ArrayIterator<T>>;\n"
            "\n"
            "public:\n"
            "    using Base::Base;\n"
            "};",
            "class ArrayIterator : public BaseArrayIterator<T, ArrayIterator<T>> {\n"
            "    using Base = BaseArrayIterator<T, ArrayIterator<T>>;\n"
            "\n"
            "public:\n"
            "    using Base::Base;\n"
            "};\n"
            "\n"
            "template <typename T>\n"
            "auto BaseArray<T>::begin() const noexcept {\n"
            "    return typename T::const_iterator(*static_cast<const T*>(this), 0);\n"
            "}\n"
            "\n"
            "template <typename T>\n"
            "auto BaseArray<T>::end() const noexcept {\n"
            "    return typename T::const_iterator(*static_cast<const T*>(this), Size_);\n"
            "}",
        )

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["YAFF_BUILD_TESTS"] = False
        tc.variables["YAFF_BUILD_BENCHMARKS"] = False
        tc.variables["YAFF_BUILD_EXAMPLES"] = False
        tc.variables["CMAKE_MACOSX_BUNDLE"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_find_mode", "none")
        self.cpp_info.builddirs = ["lib/cmake/YaFF"]
        self.cpp_info.bindirs = ["bin"]

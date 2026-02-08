import os
import re
import sys
import subprocess
from pathlib import Path

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class CMakeExtension(Extension):
    def __init__(self, name: str, sourcedir: str = "") -> None:
        super().__init__(name, sources=[])
        self.sourcedir = os.fspath(Path(sourcedir).resolve())


class CMakeBuild(build_ext):
    def build_extension(self, ext: CMakeExtension) -> None:
        ext_fullpath = Path.cwd() / self.get_ext_fullpath(ext.name)
        extdir = ext_fullpath.parent.resolve()

        cmake_generator = os.environ.get("CMAKE_GENERATOR", "")

        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}{os.sep}",
            f"-DPython_EXECUTABLE={sys.executable}",
            f"-DCMAKE_BUILD_TYPE=Release",
        ]

        build_args = ["--config", "Release"]

        # On macOS, respect ARCHFLAGS for cross-compilation (e.g. x86_64 on arm64)
        archflags = os.environ.get("ARCHFLAGS", "")
        archs = re.findall(r"-arch (\S+)", archflags)
        if archs:
            cmake_args.append(f"-DCMAKE_OSX_ARCHITECTURES={';'.join(archs)}")

        # On Windows, use Ninja if no generator is specified to avoid
        # Visual Studio multi-config generator issues with pybind11
        if sys.platform == "win32" and not cmake_generator:
            try:
                import ninja
                ninja_executable_path = Path(ninja.BIN_DIR) / "ninja"
                cmake_args += [
                    "-GNinja",
                    f"-DCMAKE_MAKE_PROGRAM:FILEPATH={ninja_executable_path}",
                ]
            except ImportError:
                pass

        if "CMAKE_BUILD_PARALLEL_LEVEL" not in os.environ:
            if hasattr(self, "parallel") and self.parallel:
                build_args += [f"-j{self.parallel}"]

        build_temp = Path(self.build_temp) / ext.name
        build_temp.mkdir(parents=True, exist_ok=True)

        subprocess.run(
            ["cmake", ext.sourcedir, *cmake_args],
            cwd=build_temp,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", ".", *build_args],
            cwd=build_temp,
            check=True,
        )


setup(
    ext_modules=[CMakeExtension("fpcap._fpcap")],
    cmdclass={"build_ext": CMakeBuild},
)

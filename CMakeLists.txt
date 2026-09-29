cmake_minimum_required(VERSION 3.20)
project(BSODViewer LANGUAGES CXX RC)

if(NOT WIN32)
    message(FATAL_ERROR "BSOD Viewer is a native Windows application.")
endif()

add_executable(BSODViewer WIN32 src/main.cpp src/app.rc)
target_compile_features(BSODViewer PRIVATE cxx_std_20)
target_compile_definitions(BSODViewer PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(BSODViewer PRIVATE user32 gdi32 comctl32 dbghelp wevtapi shell32 ole32 advapi32)

if(MSVC)
    target_compile_options(BSODViewer PRIVATE /W4 /permissive- /EHsc)
    target_link_options(BSODViewer PRIVATE /MANIFEST:NO)
endif()
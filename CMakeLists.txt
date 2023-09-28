cmake_minimum_required(VERSION 3.14)

project(testm17utils LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_executable(testm17utils
  main.cpp
  m17_qt_utils.h
  README.md
  LICENSE
  m17_c_utils.h
  m17_cpp_utils.h
)

target_link_libraries(testm17utils Qt${QT_VERSION_MAJOR}::Core)

include(GNUInstallDirs)
install(TARGETS testm17utils
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

cmake_minimum_required(VERSION 3.20)
project(myfuzz_frontend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MYFUZZ_FRONTEND_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(VENDOR_SRC ${MYFUZZ_FRONTEND_DIR}/vendor/verilator/src)
set(VENDOR_INC ${MYFUZZ_FRONTEND_DIR}/vendor/verilator/include)
set(VENDOR_GEN ${MYFUZZ_FRONTEND_DIR}/vendor/verilator/generated)

set(MYFUZZ_FRONTEND_SOURCES
    src/MyFuzzFrontend.cpp
    src/MyFuzzFrontendApi.cpp
    src/MyFuzzFrontendStubs.cpp
    src/MyFuzzGlobal.cpp

    ${VENDOR_SRC}/V3Ast.cpp
    ${VENDOR_SRC}/V3AstNodes.cpp
    ${VENDOR_SRC}/V3Begin.cpp
    ${VENDOR_SRC}/V3Broken.cpp
    ${VENDOR_SRC}/V3Case.cpp
    ${VENDOR_GEN}/V3Const__gen.cpp
    ${VENDOR_SRC}/V3Control.cpp
    ${VENDOR_SRC}/V3Dead.cpp
    ${VENDOR_SRC}/V3Error.cpp
    ${VENDOR_SRC}/V3File.cpp
    ${VENDOR_SRC}/V3FileLine.cpp
    ${VENDOR_SRC}/V3Graph.cpp
    ${VENDOR_SRC}/V3GraphAcyc.cpp
    ${VENDOR_SRC}/V3GraphAlg.cpp
    ${VENDOR_SRC}/V3GraphPathChecker.cpp
    ${VENDOR_SRC}/V3Hash.cpp
    ${VENDOR_SRC}/V3Hasher.cpp
    ${VENDOR_SRC}/V3InstrCount.cpp
    ${VENDOR_SRC}/V3LibMap.cpp
    ${VENDOR_SRC}/V3LinkCells.cpp
    ${VENDOR_SRC}/V3LinkDot.cpp
    ${VENDOR_SRC}/V3LinkDotIfaceCapture.cpp
    ${VENDOR_SRC}/V3LinkInc.cpp
    ${VENDOR_SRC}/V3LinkJump.cpp
    ${VENDOR_SRC}/V3LinkLValue.cpp
    ${VENDOR_SRC}/V3LinkLevel.cpp
    ${VENDOR_SRC}/V3LinkParse.cpp
    ${VENDOR_SRC}/V3LinkResolve.cpp
    ${VENDOR_SRC}/V3LinkWith.cpp
    ${VENDOR_SRC}/V3Number.cpp
    ${VENDOR_SRC}/V3OptionParser.cpp
    ${VENDOR_SRC}/V3Options.cpp
    ${VENDOR_SRC}/V3Os.cpp
    ${VENDOR_SRC}/V3Param.cpp
    ${VENDOR_SRC}/V3ParseGrammar.cpp
    ${VENDOR_SRC}/V3ParseImp.cpp
    ${VENDOR_SRC}/V3ParseLex.cpp
    ${VENDOR_SRC}/V3PreProc.cpp
    ${VENDOR_SRC}/V3PreShell.cpp
    ${VENDOR_SRC}/V3Randomize.cpp
    ${VENDOR_SRC}/V3String.cpp
    ${VENDOR_SRC}/V3Task.cpp
    ${VENDOR_SRC}/V3Udp.cpp
    ${VENDOR_SRC}/V3UnrollGen.cpp
    ${VENDOR_SRC}/V3VIFrontend.cpp
    ${VENDOR_SRC}/V3Width.cpp
    ${VENDOR_SRC}/V3WidthCommit.cpp
    ${VENDOR_SRC}/V3WidthSel.cpp
)

add_library(myfuzz_frontend SHARED ${MYFUZZ_FRONTEND_SOURCES})
target_include_directories(myfuzz_frontend
    PRIVATE
        ${MYFUZZ_FRONTEND_DIR}/src
        ${VENDOR_SRC}
        ${VENDOR_INC}
        ${VENDOR_GEN}
)
target_compile_options(myfuzz_frontend PRIVATE
    -Wno-unused-parameter
    -Wno-missing-field-initializers
)
target_link_options(myfuzz_frontend PRIVATE
    -Wl,--no-undefined
)
set_target_properties(myfuzz_frontend PROPERTIES
    OUTPUT_NAME myfuzz_frontend
)

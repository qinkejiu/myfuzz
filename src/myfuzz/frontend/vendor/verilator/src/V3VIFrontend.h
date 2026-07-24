// -*- mode: C++; c-file-style: "cc-mode" -*-
//*************************************************************************
// DESCRIPTION: Verilator: Verilog Instrumenter frontend extraction pass
//
// This pass is intentionally a source-level bridge: it runs after parsing,
// linking, parameter elaboration, and width calculation, but before Verilator
// optimization/lowering passes.  It exports source locations, module ports,
// instance edges, and branch candidates for an external source rewriter.
//*************************************************************************

#ifndef VERILATOR_V3VIFRONTEND_H_
#define VERILATOR_V3VIFRONTEND_H_

#include "config_build.h"
#include "verilatedos.h"

class AstNetlist;

class V3VIFrontend final {
public:
    static void emitManifest(AstNetlist* rootp) VL_MT_DISABLED;
    static string manifestJson(AstNetlist* rootp) VL_MT_DISABLED;
    static string factsJson(AstNetlist* rootp, const string& inputHash) VL_MT_DISABLED;
    static void clearLastManifest() VL_MT_DISABLED;
    static const string& lastManifestJson() VL_MT_DISABLED;
};

#endif

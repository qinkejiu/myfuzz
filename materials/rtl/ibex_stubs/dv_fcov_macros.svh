// Stub file for dv_fcov_macros.svh
// 用于synthesis时禁用coverage宏

`ifndef DV_FCOV_MACROS_SVH
`define DV_FCOV_MACROS_SVH

// 将所有coverage宏定义为空
`define DV_FCOV_SIGNAL(TYPE, NAME, SIGNAL)
`define DV_FCOV_SIGNAL_GEN_IF(TYPE, NAME, SIGNAL, COND)
`define DV_FCOV_EXPR_SEEN(NAME, EXPR)

`endif // DV_FCOV_MACROS_SVH

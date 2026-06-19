/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_HOME_QINKEJIU_TEST_VERILOG_INSTRUMENTER_TEST_VERILATOR_BUILD_PROJECT_SRC_V3PARSEBISON_PRETMP_H_INCLUDED
# define YY_YY_HOME_QINKEJIU_TEST_VERILOG_INSTRUMENTER_TEST_VERILATOR_BUILD_PROJECT_SRC_V3PARSEBISON_PRETMP_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    yaFLOATNUM = 258,              /* "FLOATING-POINT NUMBER"  */
    yaID__ETC = 259,               /* "IDENTIFIER"  */
    yaID__CC = 260,                /* "IDENTIFIER-::"  */
    yaID__LEX = 261,               /* "IDENTIFIER-in-lex"  */
    yaID__PATHPULSE = 262,         /* "IDENTIFIER-for-pathpulse"  */
    yaID__aINST = 263,             /* "IDENTIFIER-for-instance"  */
    yaID__aTYPE = 264,             /* "IDENTIFIER-for-type"  */
    yaINTNUM = 265,                /* "INTEGER NUMBER"  */
    yaTIMENUM = 266,               /* "TIME NUMBER"  */
    yaSTRING = 267,                /* "STRING"  */
    yaSTRING__IGNORE = 268,        /* "STRING-ignored"  */
    yaEDGEDESC = 269,              /* "EDGE DESCRIPTOR"  */
    yaTIMINGSPEC = 270,            /* "TIMING SPEC ELEMENT"  */
    ygenSTRENGTH = 271,            /* "STRENGTH keyword (strong1/etc)"  */
    yaTABLE_FIELD = 272,           /* "UDP table field"  */
    yaTABLE_LRSEP = 273,           /* ":"  */
    yaTABLE_LINEEND = 274,         /* "UDP table line end"  */
    yaSCCTOR = 275,                /* "`systemc_ctor block"  */
    yaSCDTOR = 276,                /* "`systemc_dtor block"  */
    yaSCHDR = 277,                 /* "`systemc_header block"  */
    yaSCHDRP = 278,                /* "`systemc_header_post block"  */
    yaSCIMP = 279,                 /* "`systemc_implementation block"  */
    yaSCIMPH = 280,                /* "`systemc_imp_header block"  */
    yaSCINT = 281,                 /* "`systemc_interface block"  */
    yVLT_CLOCKER = 282,            /* "clocker"  */
    yVLT_CLOCK_ENABLE = 283,       /* "clock_enable"  */
    yVLT_COVERAGE_BLOCK_OFF = 284, /* "coverage_block_off"  */
    yVLT_COVERAGE_OFF = 285,       /* "coverage_off"  */
    yVLT_COVERAGE_ON = 286,        /* "coverage_on"  */
    yVLT_FORCEABLE = 287,          /* "forceable"  */
    yVLT_FSM_REGISTER_WRAPPER = 288, /* "fsm_register_wrapper"  */
    yVLT_FULL_CASE = 289,          /* "full_case"  */
    yVLT_HIER_BLOCK = 290,         /* "hier_block"  */
    yVLT_HIER_PARAMS = 291,        /* "hier_params"  */
    yVLT_HIER_WORKERS = 292,       /* "hier_workers"  */
    yVLT_INLINE = 293,             /* "inline"  */
    yVLT_ISOLATE_ASSIGNMENTS = 294, /* "isolate_assignments"  */
    yVLT_LINT_OFF = 295,           /* "lint_off"  */
    yVLT_LINT_ON = 296,            /* "lint_on"  */
    yVLT_NO_CLOCKER = 297,         /* "no_clocker"  */
    yVLT_NO_INLINE = 298,          /* "no_inline"  */
    yVLT_PARALLEL_CASE = 299,      /* "parallel_case"  */
    yVLT_PROFILE_DATA = 300,       /* "profile_data"  */
    yVLT_PUBLIC = 301,             /* "public"  */
    yVLT_PUBLIC_FLAT = 302,        /* "public_flat"  */
    yVLT_PUBLIC_FLAT_RD = 303,     /* "public_flat_rd"  */
    yVLT_PUBLIC_FLAT_RW = 304,     /* "public_flat_rw"  */
    yVLT_PUBLIC_MODULE = 305,      /* "public_module"  */
    yVLT_SC_BIGUINT = 306,         /* "sc_biguint"  */
    yVLT_SC_BV = 307,              /* "sc_bv"  */
    yVLT_SFORMAT = 308,            /* "sformat"  */
    yVLT_SPLIT_VAR = 309,          /* "split_var"  */
    yVLT_TIMING_OFF = 310,         /* "timing_off"  */
    yVLT_TIMING_ON = 311,          /* "timing_on"  */
    yVLT_TRACING_OFF = 312,        /* "tracing_off"  */
    yVLT_TRACING_ON = 313,         /* "tracing_on"  */
    yVLT_VERILATOR_LIB = 314,      /* "verilator_lib"  */
    yVLT_D_BLOCK = 315,            /* "--block"  */
    yVLT_D_CONTENTS = 316,         /* "--contents"  */
    yVLT_D_COST = 317,             /* "--cost"  */
    yVLT_D_CLOCK = 318,            /* "--clock"  */
    yVLT_D_D = 319,                /* "--d"  */
    yVLT_D_FILE = 320,             /* "--file"  */
    yVLT_D_FUNCTION = 321,         /* "--function"  */
    yVLT_D_HIER_DPI = 322,         /* "--hier-dpi"  */
    yVLT_D_LEVELS = 323,           /* "--levels"  */
    yVLT_D_LINES = 324,            /* "--lines"  */
    yVLT_D_MATCH = 325,            /* "--match"  */
    yVLT_D_MODEL = 326,            /* "--model"  */
    yVLT_D_MODULE = 327,           /* "--module"  */
    yVLT_D_MTASK = 328,            /* "--mtask"  */
    yVLT_D_PARAM = 329,            /* "--param"  */
    yVLT_D_PORT = 330,             /* "--port"  */
    yVLT_D_RULE = 331,             /* "--rule"  */
    yVLT_D_Q = 332,                /* "--q"  */
    yVLT_D_RESET = 333,            /* "--reset"  */
    yVLT_D_RESET_VALUE = 334,      /* "--reset_value"  */
    yVLT_D_SCOPE = 335,            /* "--scope"  */
    yVLT_D_TASK = 336,             /* "--task"  */
    yVLT_D_VAR = 337,              /* "--var"  */
    yVLT_D_WORKERS = 338,          /* "--workers"  */
    yaD_PLI = 339,                 /* "${pli-system}"  */
    yaT_NOUNCONNECTED = 340,       /* "`nounconnecteddrive"  */
    yaT_RESETALL = 341,            /* "`resetall"  */
    yaT_UNCONNECTED_PULL0 = 342,   /* "`unconnected_drive pull0"  */
    yaT_UNCONNECTED_PULL1 = 343,   /* "`unconnected_drive pull1"  */
    y1STEP = 344,                  /* "1step"  */
    yACCEPT_ON = 345,              /* "accept_on"  */
    yALIAS = 346,                  /* "alias"  */
    yALWAYS = 347,                 /* "always"  */
    yALWAYS_COMB = 348,            /* "always_comb"  */
    yALWAYS_FF = 349,              /* "always_ff"  */
    yALWAYS_LATCH = 350,           /* "always_latch"  */
    yAND = 351,                    /* "and"  */
    yASSERT = 352,                 /* "assert"  */
    yASSIGN = 353,                 /* "assign"  */
    yASSUME = 354,                 /* "assume"  */
    yAUTOMATIC = 355,              /* "automatic"  */
    yBEFORE = 356,                 /* "before"  */
    yBEGIN = 357,                  /* "begin"  */
    yBIND = 358,                   /* "bind"  */
    yBINS = 359,                   /* "bins"  */
    yBINSOF = 360,                 /* "binsof"  */
    yBIT = 361,                    /* "bit"  */
    yBREAK = 362,                  /* "break"  */
    yBUF = 363,                    /* "buf"  */
    yBUFIF0 = 364,                 /* "bufif0"  */
    yBUFIF1 = 365,                 /* "bufif1"  */
    yBYTE = 366,                   /* "byte"  */
    yCASE = 367,                   /* "case"  */
    yCASEX = 368,                  /* "casex"  */
    yCASEZ = 369,                  /* "casez"  */
    yCELL = 370,                   /* "cell"  */
    yCHANDLE = 371,                /* "chandle"  */
    yCHECKER = 372,                /* "checker"  */
    yCLASS = 373,                  /* "class"  */
    yCLOCKING = 374,               /* "clocking"  */
    yCMOS = 375,                   /* "cmos"  */
    yCONFIG = 376,                 /* "config"  */
    yCONSTRAINT = 377,             /* "constraint"  */
    yCONST__ETC = 378,             /* "const"  */
    yCONST__LEX = 379,             /* "const-in-lex"  */
    yCONST__REF = 380,             /* "const-then-ref"  */
    yCONTEXT = 381,                /* "context"  */
    yCONTINUE = 382,               /* "continue"  */
    yCOVER = 383,                  /* "cover"  */
    yCOVERGROUP = 384,             /* "covergroup"  */
    yCOVERPOINT = 385,             /* "coverpoint"  */
    yCROSS = 386,                  /* "cross"  */
    yDEASSIGN = 387,               /* "deassign"  */
    yDEFAULT = 388,                /* "default"  */
    yDEFPARAM = 389,               /* "defparam"  */
    yDESIGN = 390,                 /* "design"  */
    yDISABLE = 391,                /* "disable"  */
    yDIST = 392,                   /* "dist"  */
    yDO = 393,                     /* "do"  */
    yEDGE = 394,                   /* "edge"  */
    yELSE = 395,                   /* "else"  */
    yEND = 396,                    /* "end"  */
    yENDCASE = 397,                /* "endcase"  */
    yENDCHECKER = 398,             /* "endchecker"  */
    yENDCLASS = 399,               /* "endclass"  */
    yENDCLOCKING = 400,            /* "endclocking"  */
    yENDCONFIG = 401,              /* "endconfig"  */
    yENDFUNCTION = 402,            /* "endfunction"  */
    yENDGENERATE = 403,            /* "endgenerate"  */
    yENDGROUP = 404,               /* "endgroup"  */
    yENDINTERFACE = 405,           /* "endinterface"  */
    yENDMODULE = 406,              /* "endmodule"  */
    yENDPACKAGE = 407,             /* "endpackage"  */
    yENDPRIMITIVE = 408,           /* "endprimitive"  */
    yENDPROGRAM = 409,             /* "endprogram"  */
    yENDPROPERTY = 410,            /* "endproperty"  */
    yENDSEQUENCE = 411,            /* "endsequence"  */
    yENDSPECIFY = 412,             /* "endspecify"  */
    yENDTABLE = 413,               /* "endtable"  */
    yENDTASK = 414,                /* "endtask"  */
    yENUM = 415,                   /* "enum"  */
    yEVENT = 416,                  /* "event"  */
    yEVENTUALLY = 417,             /* "eventually"  */
    yEXPECT = 418,                 /* "expect"  */
    yEXPORT = 419,                 /* "export"  */
    yEXTENDS = 420,                /* "extends"  */
    yEXTERN = 421,                 /* "extern"  */
    yFINAL = 422,                  /* "final"  */
    yFIRST_MATCH = 423,            /* "first_match"  */
    yFOR = 424,                    /* "for"  */
    yFORCE = 425,                  /* "force"  */
    yFOREACH = 426,                /* "foreach"  */
    yFOREVER = 427,                /* "forever"  */
    yFORK = 428,                   /* "fork"  */
    yFORKJOIN = 429,               /* "forkjoin"  */
    yFUNCTION = 430,               /* "function"  */
    yGENERATE = 431,               /* "generate"  */
    yGENVAR = 432,                 /* "genvar"  */
    yGLOBAL__CLOCKING = 433,       /* "global-then-clocking"  */
    yGLOBAL__ETC = 434,            /* "global"  */
    yGLOBAL__LEX = 435,            /* "global-in-lex"  */
    yHIGHZ0 = 436,                 /* "highz0"  */
    yHIGHZ1 = 437,                 /* "highz1"  */
    yIF = 438,                     /* "if"  */
    yIFF = 439,                    /* "iff"  */
    yIGNORE_BINS = 440,            /* "ignore_bins"  */
    yILLEGAL_BINS = 441,           /* "illegal_bins"  */
    yIMPLEMENTS = 442,             /* "implements"  */
    yIMPLIES = 443,                /* "implies"  */
    yIMPORT = 444,                 /* "import"  */
    yINCDIR = 445,                 /* "incdir"  */
    yINCLUDE = 446,                /* "include"  */
    yINITIAL = 447,                /* "initial"  */
    yINOUT = 448,                  /* "inout"  */
    yINPUT = 449,                  /* "input"  */
    yINSIDE = 450,                 /* "inside"  */
    yINSTANCE = 451,               /* "instance"  */
    yINT = 452,                    /* "int"  */
    yINTEGER = 453,                /* "integer"  */
    yINTERCONNECT = 454,           /* "interconnect"  */
    yINTERFACE = 455,              /* "interface"  */
    yINTERSECT = 456,              /* "intersect"  */
    yJOIN = 457,                   /* "join"  */
    yJOIN_ANY = 458,               /* "join_any"  */
    yJOIN_NONE = 459,              /* "join_none"  */
    yLET = 460,                    /* "let"  */
    yLIBLIST = 461,                /* "liblist"  */
    yLIBRARY = 462,                /* "library"  */
    yLOCALPARAM = 463,             /* "localparam"  */
    yLOCAL__COLONCOLON = 464,      /* "local-then-::"  */
    yLOCAL__ETC = 465,             /* "local"  */
    yLOCAL__LEX = 466,             /* "local-in-lex"  */
    yLOGIC = 467,                  /* "logic"  */
    yLONGINT = 468,                /* "longint"  */
    yMATCHES = 469,                /* "matches"  */
    yMODPORT = 470,                /* "modport"  */
    yMODULE = 471,                 /* "module"  */
    yNAND = 472,                   /* "nand"  */
    yNEGEDGE = 473,                /* "negedge"  */
    yNETTYPE = 474,                /* "nettype"  */
    yNEW__ETC = 475,               /* "new"  */
    yNEW__LEX = 476,               /* "new-in-lex"  */
    yNEW__PAREN = 477,             /* "new-then-paren"  */
    yNEXTTIME = 478,               /* "nexttime"  */
    yNMOS = 479,                   /* "nmos"  */
    yNOR = 480,                    /* "nor"  */
    yNOT = 481,                    /* "not"  */
    yNOTIF0 = 482,                 /* "notif0"  */
    yNOTIF1 = 483,                 /* "notif1"  */
    yNULL = 484,                   /* "null"  */
    yOR = 485,                     /* "or"  */
    yOUTPUT = 486,                 /* "output"  */
    yPACKAGE = 487,                /* "package"  */
    yPACKED = 488,                 /* "packed"  */
    yPARAMETER = 489,              /* "parameter"  */
    yPMOS = 490,                   /* "pmos"  */
    yPOSEDGE = 491,                /* "posedge"  */
    yPRIMITIVE = 492,              /* "primitive"  */
    yPRIORITY = 493,               /* "priority"  */
    yPROGRAM = 494,                /* "program"  */
    yPROPERTY = 495,               /* "property"  */
    yPROTECTED = 496,              /* "protected"  */
    yPULL0 = 497,                  /* "pull0"  */
    yPULL1 = 498,                  /* "pull1"  */
    yPULLDOWN = 499,               /* "pulldown"  */
    yPULLUP = 500,                 /* "pullup"  */
    yPURE = 501,                   /* "pure"  */
    yRAND = 502,                   /* "rand"  */
    yRANDC = 503,                  /* "randc"  */
    yRANDCASE = 504,               /* "randcase"  */
    yRANDOMIZE = 505,              /* "randomize"  */
    yRANDSEQUENCE = 506,           /* "randsequence"  */
    yRCMOS = 507,                  /* "rcmos"  */
    yREAL = 508,                   /* "real"  */
    yREALTIME = 509,               /* "realtime"  */
    yREF = 510,                    /* "ref"  */
    yREG = 511,                    /* "reg"  */
    yREJECT_ON = 512,              /* "reject_on"  */
    yRELEASE = 513,                /* "release"  */
    yREPEAT = 514,                 /* "repeat"  */
    yRESTRICT = 515,               /* "restrict"  */
    yRETURN = 516,                 /* "return"  */
    yRNMOS = 517,                  /* "rnmos"  */
    yRPMOS = 518,                  /* "rpmos"  */
    yRTRAN = 519,                  /* "rtran"  */
    yRTRANIF0 = 520,               /* "rtranif0"  */
    yRTRANIF1 = 521,               /* "rtranif1"  */
    ySCALARED = 522,               /* "scalared"  */
    ySEQUENCE = 523,               /* "sequence"  */
    ySHORTINT = 524,               /* "shortint"  */
    ySHORTREAL = 525,              /* "shortreal"  */
    ySIGNED = 526,                 /* "signed"  */
    ySOFT = 527,                   /* "soft"  */
    ySOLVE = 528,                  /* "solve"  */
    ySPECIFY = 529,                /* "specify"  */
    ySPECPARAM = 530,              /* "specparam"  */
    ySTATIC__CONSTRAINT = 531,     /* "static-then-constraint"  */
    ySTATIC__ETC = 532,            /* "static"  */
    ySTATIC__LEX = 533,            /* "static-in-lex"  */
    ySTRING = 534,                 /* "string"  */
    ySTRONG = 535,                 /* "strong"  */
    ySTRONG0 = 536,                /* "strong0"  */
    ySTRONG1 = 537,                /* "strong1"  */
    ySTRUCT = 538,                 /* "struct"  */
    ySUPER = 539,                  /* "super"  */
    ySUPPLY0 = 540,                /* "supply0"  */
    ySUPPLY1 = 541,                /* "supply1"  */
    ySYNC_ACCEPT_ON = 542,         /* "sync_accept_on"  */
    ySYNC_REJECT_ON = 543,         /* "sync_reject_on"  */
    yS_ALWAYS = 544,               /* "s_always"  */
    yS_EVENTUALLY = 545,           /* "s_eventually"  */
    yS_NEXTTIME = 546,             /* "s_nexttime"  */
    yS_UNTIL = 547,                /* "s_until"  */
    yS_UNTIL_WITH = 548,           /* "s_until_with"  */
    yTABLE = 549,                  /* "table"  */
    yTAGGED = 550,                 /* "tagged"  */
    yTAGGED__LEX = 551,            /* "tagged-in-lex"  */
    yTAGGED__NONPRIMARY = 552,     /* "tagged-nonprimary"  */
    yTASK = 553,                   /* "task"  */
    yTHIS = 554,                   /* "this"  */
    yTHROUGHOUT = 555,             /* "throughout"  */
    yTIME = 556,                   /* "time"  */
    yTIMEPRECISION = 557,          /* "timeprecision"  */
    yTIMEUNIT = 558,               /* "timeunit"  */
    yTRAN = 559,                   /* "tran"  */
    yTRANIF0 = 560,                /* "tranif0"  */
    yTRANIF1 = 561,                /* "tranif1"  */
    yTRI = 562,                    /* "tri"  */
    yTRI0 = 563,                   /* "tri0"  */
    yTRI1 = 564,                   /* "tri1"  */
    yTRIAND = 565,                 /* "triand"  */
    yTRIOR = 566,                  /* "trior"  */
    yTRIREG = 567,                 /* "trireg"  */
    yTRUE = 568,                   /* "true"  */
    yTYPEDEF = 569,                /* "typedef"  */
    yTYPE__EQ = 570,               /* "type-then-eqneq"  */
    yTYPE__ETC = 571,              /* "type"  */
    yTYPE__LEX = 572,              /* "type-in-lex"  */
    yUNION = 573,                  /* "union"  */
    yUNIQUE = 574,                 /* "unique"  */
    yUNIQUE0 = 575,                /* "unique0"  */
    yUNSIGNED = 576,               /* "unsigned"  */
    yUNTIL = 577,                  /* "until"  */
    yUNTIL_WITH = 578,             /* "until_with"  */
    yUNTYPED = 579,                /* "untyped"  */
    yUSE = 580,                    /* "use"  */
    yVAR = 581,                    /* "var"  */
    yVECTORED = 582,               /* "vectored"  */
    yVIRTUAL__CLASS = 583,         /* "virtual-then-class"  */
    yVIRTUAL__ETC = 584,           /* "virtual"  */
    yVIRTUAL__INTERFACE = 585,     /* "virtual-then-interface"  */
    yVIRTUAL__LEX = 586,           /* "virtual-in-lex"  */
    yVIRTUAL__anyID = 587,         /* "virtual-then-identifier"  */
    yVOID = 588,                   /* "void"  */
    yWAIT = 589,                   /* "wait"  */
    yWAIT_ORDER = 590,             /* "wait_order"  */
    yWAND = 591,                   /* "wand"  */
    yWEAK = 592,                   /* "weak"  */
    yWEAK0 = 593,                  /* "weak0"  */
    yWEAK1 = 594,                  /* "weak1"  */
    yWHILE = 595,                  /* "while"  */
    yWILDCARD = 596,               /* "wildcard"  */
    yWIRE = 597,                   /* "wire"  */
    yWITHIN = 598,                 /* "within"  */
    yWITH__BRA = 599,              /* "with-then-["  */
    yWITH__CUR = 600,              /* "with-then-{"  */
    yWITH__ETC = 601,              /* "with"  */
    yWITH__LEX = 602,              /* "with-in-lex"  */
    yWITH__PAREN = 603,            /* "with-then-("  */
    yWITH__PAREN_CUR = 604,        /* "with-then-(-then-{"  */
    yWOR = 605,                    /* "wor"  */
    yWREAL = 606,                  /* "wreal"  */
    yXNOR = 607,                   /* "xnor"  */
    yXOR = 608,                    /* "xor"  */
    yD_ACOS = 609,                 /* "$acos"  */
    yD_ACOSH = 610,                /* "$acosh"  */
    yD_ASIN = 611,                 /* "$asin"  */
    yD_ASINH = 612,                /* "$asinh"  */
    yD_ASSERTCTL = 613,            /* "$assertcontrol"  */
    yD_ASSERTFAILOFF = 614,        /* "$assertfailoff"  */
    yD_ASSERTFAILON = 615,         /* "$assertfailon"  */
    yD_ASSERTKILL = 616,           /* "$assertkill"  */
    yD_ASSERTNONVACUOUSON = 617,   /* "$assertnonvacuouson"  */
    yD_ASSERTOFF = 618,            /* "$assertoff"  */
    yD_ASSERTON = 619,             /* "$asserton"  */
    yD_ASSERTPASSOFF = 620,        /* "$assertpassoff"  */
    yD_ASSERTPASSON = 621,         /* "$assertpasson"  */
    yD_ASSERTVACUOUSOFF = 622,     /* "$assertvacuousoff"  */
    yD_ATAN = 623,                 /* "$atan"  */
    yD_ATAN2 = 624,                /* "$atan2"  */
    yD_ATANH = 625,                /* "$atanh"  */
    yD_BITS = 626,                 /* "$bits"  */
    yD_BITSTOREAL = 627,           /* "$bitstoreal"  */
    yD_BITSTOSHORTREAL = 628,      /* "$bitstoshortreal"  */
    yD_C = 629,                    /* "$c"  */
    yD_CPURE = 630,                /* "$cpure"  */
    yD_CAST = 631,                 /* "$cast"  */
    yD_CEIL = 632,                 /* "$ceil"  */
    yD_CHANGED = 633,              /* "$changed"  */
    yD_CHANGED_GCLK = 634,         /* "$changed_gclk"  */
    yD_CHANGING_GCLK = 635,        /* "$changing_gclk"  */
    yD_CLOG2 = 636,                /* "$clog2"  */
    yD_COS = 637,                  /* "$cos"  */
    yD_COSH = 638,                 /* "$cosh"  */
    yD_COUNTBITS = 639,            /* "$countbits"  */
    yD_COUNTONES = 640,            /* "$countones"  */
    yD_DIMENSIONS = 641,           /* "$dimensions"  */
    yD_DISPLAY = 642,              /* "$display"  */
    yD_DISPLAYB = 643,             /* "$displayb"  */
    yD_DISPLAYH = 644,             /* "$displayh"  */
    yD_DISPLAYO = 645,             /* "$displayo"  */
    yD_DIST_CHI_SQUARE = 646,      /* "$dist_chi_square"  */
    yD_DIST_ERLANG = 647,          /* "$dist_erlang"  */
    yD_DIST_EXPONENTIAL = 648,     /* "$dist_exponential"  */
    yD_DIST_NORMAL = 649,          /* "$dist_normal"  */
    yD_DIST_POISSON = 650,         /* "$dist_poisson"  */
    yD_DIST_T = 651,               /* "$dist_t"  */
    yD_DIST_UNIFORM = 652,         /* "$dist_uniform"  */
    yD_DUMPALL = 653,              /* "$dumpall"  */
    yD_DUMPFILE = 654,             /* "$dumpfile"  */
    yD_DUMPFLUSH = 655,            /* "$dumpflush"  */
    yD_DUMPLIMIT = 656,            /* "$dumplimit"  */
    yD_DUMPOFF = 657,              /* "$dumpoff"  */
    yD_DUMPON = 658,               /* "$dumpon"  */
    yD_DUMPPORTS = 659,            /* "$dumpports"  */
    yD_DUMPVARS = 660,             /* "$dumpvars"  */
    yD_ERROR = 661,                /* "$error"  */
    yD_EXIT = 662,                 /* "$exit"  */
    yD_EXP = 663,                  /* "$exp"  */
    yD_FALLING_GCLK = 664,         /* "$falling_gclk"  */
    yD_FATAL = 665,                /* "$fatal"  */
    yD_FCLOSE = 666,               /* "$fclose"  */
    yD_FDISPLAY = 667,             /* "$fdisplay"  */
    yD_FDISPLAYB = 668,            /* "$fdisplayb"  */
    yD_FDISPLAYH = 669,            /* "$fdisplayh"  */
    yD_FDISPLAYO = 670,            /* "$fdisplayo"  */
    yD_FELL = 671,                 /* "$fell"  */
    yD_FELL_GCLK = 672,            /* "$fell_gclk"  */
    yD_FEOF = 673,                 /* "$feof"  */
    yD_FERROR = 674,               /* "$ferror"  */
    yD_FFLUSH = 675,               /* "$fflush"  */
    yD_FGETC = 676,                /* "$fgetc"  */
    yD_FGETS = 677,                /* "$fgets"  */
    yD_FINISH = 678,               /* "$finish"  */
    yD_FLOOR = 679,                /* "$floor"  */
    yD_FMONITOR = 680,             /* "$fmonitor"  */
    yD_FMONITORB = 681,            /* "$fmonitorb"  */
    yD_FMONITORH = 682,            /* "$fmonitorh"  */
    yD_FMONITORO = 683,            /* "$fmonitoro"  */
    yD_FOPEN = 684,                /* "$fopen"  */
    yD_FREAD = 685,                /* "$fread"  */
    yD_FREWIND = 686,              /* "$frewind"  */
    yD_FSCANF = 687,               /* "$fscanf"  */
    yD_FSEEK = 688,                /* "$fseek"  */
    yD_FSTROBE = 689,              /* "$fstrobe"  */
    yD_FSTROBEB = 690,             /* "$fstrobeb"  */
    yD_FSTROBEH = 691,             /* "$fstrobeh"  */
    yD_FSTROBEO = 692,             /* "$fstrobeo"  */
    yD_FTELL = 693,                /* "$ftell"  */
    yD_FUTURE_GCLK = 694,          /* "$future_gclk"  */
    yD_FWRITE = 695,               /* "$fwrite"  */
    yD_FWRITEB = 696,              /* "$fwriteb"  */
    yD_FWRITEH = 697,              /* "$fwriteh"  */
    yD_FWRITEO = 698,              /* "$fwriteo"  */
    yD_GET_INITIAL_RANDOM_SEED = 699, /* "$get_initial_random_seed"  */
    yD_GLOBAL_CLOCK = 700,         /* "$global_clock"  */
    yD_HIGH = 701,                 /* "$high"  */
    yD_HYPOT = 702,                /* "$hypot"  */
    yD_INCREMENT = 703,            /* "$increment"  */
    yD_INFERRED_DISABLE = 704,     /* "$inferred_disable"  */
    yD_INFO = 705,                 /* "$info"  */
    yD_ISUNBOUNDED = 706,          /* "$isunbounded"  */
    yD_ISUNKNOWN = 707,            /* "$isunknown"  */
    yD_ITOR = 708,                 /* "$itor"  */
    yD_LEFT = 709,                 /* "$left"  */
    yD_LN = 710,                   /* "$ln"  */
    yD_LOG10 = 711,                /* "$log10"  */
    yD_LOW = 712,                  /* "$low"  */
    yD_MONITOR = 713,              /* "$monitor"  */
    yD_MONITORB = 714,             /* "$monitorb"  */
    yD_MONITORH = 715,             /* "$monitorh"  */
    yD_MONITORO = 716,             /* "$monitoro"  */
    yD_MONITOROFF = 717,           /* "$monitoroff"  */
    yD_MONITORON = 718,            /* "$monitoron"  */
    yD_ONEHOT = 719,               /* "$onehot"  */
    yD_ONEHOT0 = 720,              /* "$onehot0"  */
    yD_PAST = 721,                 /* "$past"  */
    yD_PAST_GCLK = 722,            /* "$past_gclk"  */
    yD_POW = 723,                  /* "$pow"  */
    yD_PRINTTIMESCALE = 724,       /* "$printtimescale"  */
    yD_RANDOM = 725,               /* "$random"  */
    yD_READMEMB = 726,             /* "$readmemb"  */
    yD_READMEMH = 727,             /* "$readmemh"  */
    yD_REALTIME = 728,             /* "$realtime"  */
    yD_REALTOBITS = 729,           /* "$realtobits"  */
    yD_REWIND = 730,               /* "$rewind"  */
    yD_RIGHT = 731,                /* "$right"  */
    yD_RISING_GCLK = 732,          /* "$rising_gclk"  */
    yD_ROOT = 733,                 /* "$root"  */
    yD_ROSE = 734,                 /* "$rose"  */
    yD_ROSE_GCLK = 735,            /* "$rose_gclk"  */
    yD_RTOI = 736,                 /* "$rtoi"  */
    yD_SAMPLED = 737,              /* "$sampled"  */
    yD_SDF_ANNOTATE = 738,         /* "$sdf_annotate"  */
    yD_SETUPHOLD = 739,            /* "$setuphold"  */
    yD_SFORMAT = 740,              /* "$sformat"  */
    yD_SFORMATF = 741,             /* "$sformatf"  */
    yD_SHORTREALTOBITS = 742,      /* "$shortrealtobits"  */
    yD_SIGNED = 743,               /* "$signed"  */
    yD_SIN = 744,                  /* "$sin"  */
    yD_SINH = 745,                 /* "$sinh"  */
    yD_SIZE = 746,                 /* "$size"  */
    yD_SQRT = 747,                 /* "$sqrt"  */
    yD_SSCANF = 748,               /* "$sscanf"  */
    yD_STABLE = 749,               /* "$stable"  */
    yD_STABLE_GCLK = 750,          /* "$stable_gclk"  */
    yD_STACKTRACE = 751,           /* "$stacktrace"  */
    yD_STEADY_GCLK = 752,          /* "$steady_gclk"  */
    yD_STIME = 753,                /* "$stime"  */
    yD_STOP = 754,                 /* "$stop"  */
    yD_STROBE = 755,               /* "$strobe"  */
    yD_STROBEB = 756,              /* "$strobeb"  */
    yD_STROBEH = 757,              /* "$strobeh"  */
    yD_STROBEO = 758,              /* "$strobeo"  */
    yD_SWRITE = 759,               /* "$swrite"  */
    yD_SWRITEB = 760,              /* "$swriteb"  */
    yD_SWRITEH = 761,              /* "$swriteh"  */
    yD_SWRITEO = 762,              /* "$swriteo"  */
    yD_SYSTEM = 763,               /* "$system"  */
    yD_TAN = 764,                  /* "$tan"  */
    yD_TANH = 765,                 /* "$tanh"  */
    yD_TESTPLUSARGS = 766,         /* "$test$plusargs"  */
    yD_TIME = 767,                 /* "$time"  */
    yD_TIMEFORMAT = 768,           /* "$timeformat"  */
    yD_TIMEPRECISION = 769,        /* "$timeprecision"  */
    yD_TIMEUNIT = 770,             /* "$timeunit"  */
    yD_TYPENAME = 771,             /* "$typename"  */
    yD_UNGETC = 772,               /* "$ungetc"  */
    yD_UNIT = 773,                 /* "$unit"  */
    yD_UNPACKED_DIMENSIONS = 774,  /* "$unpacked_dimensions"  */
    yD_UNSIGNED = 775,             /* "$unsigned"  */
    yD_URANDOM = 776,              /* "$urandom"  */
    yD_URANDOM_RANGE = 777,        /* "$urandom_range"  */
    yD_VALUEPLUSARGS = 778,        /* "$value$plusargs"  */
    yD_WARNING = 779,              /* "$warning"  */
    yD_WRITE = 780,                /* "$write"  */
    yD_WRITEB = 781,               /* "$writeb"  */
    yD_WRITEH = 782,               /* "$writeh"  */
    yD_WRITEMEMB = 783,            /* "$writememb"  */
    yD_WRITEMEMH = 784,            /* "$writememh"  */
    yD_WRITEO = 785,               /* "$writeo"  */
    yVL_CLOCKER = 786,             /* "/\*verilator clocker*\/"  */
    yVL_CLOCK_ENABLE = 787,        /* "/\*verilator clock_enable*\/"  */
    yVL_COVERAGE_BLOCK_OFF = 788,  /* "/\*verilator coverage_block_off*\/"  */
    yVL_FORCEABLE = 789,           /* "/\*verilator forceable*\/"  */
    yVL_FULL_CASE = 790,           /* "/\*verilator full_case*\/"  */
    yVL_HIER_BLOCK = 791,          /* "/\*verilator hier_block*\/"  */
    yVL_INLINE_MODULE = 792,       /* "/\*verilator inline_module*\/"  */
    yVL_ISOLATE_ASSIGNMENTS = 793, /* "/\*verilator isolate_assignments*\/"  */
    yVL_NO_CLOCKER = 794,          /* "/\*verilator no_clocker*\/"  */
    yVL_NO_INLINE_MODULE = 795,    /* "/\*verilator no_inline_module*\/"  */
    yVL_NO_INLINE_TASK = 796,      /* "/\*verilator no_inline_task*\/"  */
    yVL_PARALLEL_CASE = 797,       /* "/\*verilator parallel_case*\/"  */
    yVL_PUBLIC = 798,              /* "/\*verilator public*\/"  */
    yVL_PUBLIC_FLAT = 799,         /* "/\*verilator public_flat*\/"  */
    yVL_PUBLIC_FLAT_ON = 800,      /* "/\*verilator public_flat_on*\/"  */
    yVL_PUBLIC_FLAT_RD = 801,      /* "/\*verilator public_flat_rd*\/"  */
    yVL_PUBLIC_FLAT_RD_ON = 802,   /* "/\*verilator public_flat_rd_on*\/"  */
    yVL_PUBLIC_FLAT_RW = 803,      /* "/\*verilator public_flat_rw*\/"  */
    yVL_PUBLIC_FLAT_RW_ON = 804,   /* "/\*verilator public_flat_rw_on*\/"  */
    yVL_PUBLIC_FLAT_RW_ON_SNS = 805, /* "/\*verilator public_flat_rw_on_sns*\/"  */
    yVL_PUBLIC_ON = 806,           /* "/\*verilator public_on*\/"  */
    yVL_PUBLIC_OFF = 807,          /* "/\*verilator public_off*\/"  */
    yVL_PUBLIC_MODULE = 808,       /* "/\*verilator public_module*\/"  */
    yVL_SC_BIGUINT = 809,          /* "/\*verilator sc_biguint*\/"  */
    yVL_SC_BV = 810,               /* "/\*verilator sc_bv*\/"  */
    yVL_SFORMAT = 811,             /* "/\*verilator sformat*\/"  */
    yVL_SPLIT_VAR = 812,           /* "/\*verilator split_var*\/"  */
    yVL_FSM_ARC_INCL_COND = 813,   /* "/\*verilator fsm_arc_include_cond*\/"  */
    yVL_FSM_RESET_ARC = 814,       /* "/\*verilator fsm_reset_arc*\/"  */
    yVL_FSM_STATE = 815,           /* "/\*verilator fsm_state*\/"  */
    yVL_TAG = 816,                 /* "/\*verilator tag*\/"  */
    yVL_UNROLL_DISABLE = 817,      /* "/\*verilator unroll_disable*\/"  */
    yVL_UNROLL_FULL = 818,         /* "/\*verilator unroll_full*\/"  */
    yP_TICK = 819,                 /* "'"  */
    yP_TICKBRA = 820,              /* "'{"  */
    yP_OROR = 821,                 /* "||"  */
    yP_ANDAND = 822,               /* "&&"  */
    yP_NOR = 823,                  /* "~|"  */
    yP_XNOR = 824,                 /* "^~"  */
    yP_NAND = 825,                 /* "~&"  */
    yP_EQUAL = 826,                /* "=="  */
    yP_NOTEQUAL = 827,             /* "!="  */
    yP_CASEEQUAL = 828,            /* "==="  */
    yP_CASENOTEQUAL = 829,         /* "!=="  */
    yP_WILDEQUAL = 830,            /* "==?"  */
    yP_WILDNOTEQUAL = 831,         /* "!=?"  */
    yP_GTE = 832,                  /* ">="  */
    yP_LTE = 833,                  /* "<="  */
    yP_LTE__IGNORE = 834,          /* "<=-ignored"  */
    yP_SLEFT = 835,                /* "<<"  */
    yP_SRIGHT = 836,               /* ">>"  */
    yP_SSRIGHT = 837,              /* ">>>"  */
    yP_POW = 838,                  /* "**"  */
    yP_COLON__BEGIN = 839,         /* ":-then-begin"  */
    yP_COLON__FORK = 840,          /* ":-then-fork"  */
    yP_EQ__NEW = 841,              /* "=-then-new"  */
    yP_PAR__IGNORE = 842,          /* "(-ignored"  */
    yP_PAR__STRENGTH = 843,        /* "(-for-strength"  */
    yP_LTMINUSGT = 844,            /* "<->"  */
    yP_PLUSCOLON = 845,            /* "+:"  */
    yP_MINUSCOLON = 846,           /* "-:"  */
    yP_MINUSGT = 847,              /* "->"  */
    yP_MINUSGTGT = 848,            /* "->>"  */
    yP_EQGT = 849,                 /* "=>"  */
    yP_ASTGT = 850,                /* "*>"  */
    yP_ANDANDAND = 851,            /* "&&&"  */
    yP_POUNDPOUND = 852,           /* "##"  */
    yP_POUNDMINUSPD = 853,         /* "#-#"  */
    yP_POUNDEQPD = 854,            /* "#=#"  */
    yP_DOTSTAR = 855,              /* ".*"  */
    yP_ATAT = 856,                 /* "@@"  */
    yP_COLONCOLON = 857,           /* "::"  */
    yP_COLONEQ = 858,              /* ":="  */
    yP_COLONDIV = 859,             /* ":/"  */
    yP_ORMINUSGT = 860,            /* "|->"  */
    yP_OREQGT = 861,               /* "|=>"  */
    yP_BRASTAR = 862,              /* "[*"  */
    yP_BRAEQ = 863,                /* "[="  */
    yP_BRAMINUSGT = 864,           /* "[->"  */
    yP_BRAPLUSKET = 865,           /* "[+]"  */
    yP_PLUSPLUS = 866,             /* "++"  */
    yP_MINUSMINUS = 867,           /* "--"  */
    yP_PLUSEQ = 868,               /* "+="  */
    yP_MINUSEQ = 869,              /* "-="  */
    yP_TIMESEQ = 870,              /* "*="  */
    yP_DIVEQ = 871,                /* "/="  */
    yP_MODEQ = 872,                /* "%="  */
    yP_ANDEQ = 873,                /* "&="  */
    yP_OREQ = 874,                 /* "|="  */
    yP_XOREQ = 875,                /* "^="  */
    yP_SLEFTEQ = 876,              /* "<<="  */
    yP_SRIGHTEQ = 877,             /* ">>="  */
    yP_SSRIGHTEQ = 878,            /* ">>>="  */
    yP_PLUSSLASHMINUS = 879,       /* "+/-"  */
    yP_PLUSPCTMINUS = 880,         /* "+%-"  */
    prTAGGED = 881,                /* prTAGGED  */
    prALWAYS = 882,                /* prALWAYS  */
    prS_ALWAYS = 883,              /* prS_ALWAYS  */
    prEVENTUALLY = 884,            /* prEVENTUALLY  */
    prS_EVENTUALLY = 885,          /* prS_EVENTUALLY  */
    prIF = 886,                    /* prIF  */
    prACCEPT_ON = 887,             /* prACCEPT_ON  */
    prREJECT_ON = 888,             /* prREJECT_ON  */
    prSYNC_ACCEPT_ON = 889,        /* prSYNC_ACCEPT_ON  */
    prSYNC_REJECT_ON = 890,        /* prSYNC_REJECT_ON  */
    prPOUNDPOUND_MULTI = 891,      /* prPOUNDPOUND_MULTI  */
    prUNARYARITH = 892,            /* prUNARYARITH  */
    prREDUCTION = 893,             /* prREDUCTION  */
    prNEGATION = 894,              /* prNEGATION  */
    prLOWER_THAN_ELSE = 895        /* prLOWER_THAN_ELSE  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_HOME_QINKEJIU_TEST_VERILOG_INSTRUMENTER_TEST_VERILATOR_BUILD_PROJECT_SRC_V3PARSEBISON_PRETMP_H_INCLUDED  */

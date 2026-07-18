# Protocol Materials

This tree contains physical CPU/IP material cases organized by protocol and train/test split.

Directory shape:

```text
<protocol>/<train|test>/<role>/<material_id>/
  material.yaml
  sources.f
  rtl/
```

There is no central all/train/test manifest. Consumers should walk this directory tree.

Protocol summary:

- `ahb_lite`: total=1, train=1, test=0, cases_with_missing_entries=0
- `apb`: total=13, train=6, test=7, cases_with_missing_entries=0
- `apb_to_peripheral`: total=1, train=0, test=1, cases_with_missing_entries=0
- `axi`: total=8, train=4, test=4, cases_with_missing_entries=0
- `axi_lite`: total=5, train=2, test=3, cases_with_missing_entries=0
- `axi_lite_to_apb`: total=1, train=0, test=1, cases_with_missing_entries=0
- `axi_to_mem`: total=1, train=0, test=1, cases_with_missing_entries=0
- `native_cpu`: total=2, train=2, test=0, cases_with_missing_entries=0
- `obi`: total=2, train=0, test=2, cases_with_missing_entries=0
- `rvx_native`: total=6, train=3, test=3, cases_with_missing_entries=0
- `simple_mmio`: total=159, train=124, test=35, cases_with_missing_entries=0
- `tilelink`: total=3, train=2, test=1, cases_with_missing_entries=0
- `tlul`: total=27, train=11, test=16, cases_with_missing_entries=0
- `unknown`: total=2, train=0, test=2, cases_with_missing_entries=0
- `wishbone`: total=3, train=3, test=0, cases_with_missing_entries=0

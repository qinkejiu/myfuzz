# 单进程 IRQ 探索记录

这是 OBI CPU + APB Timer IRQ 探索，不是完整通用执行器或 RTL SoC。两份独立真实 Verilator 模型由宿主 C++ 实现 RAM、MMIO 路由和 IRQ 脉冲传递；当前源码 `scripts/inprocess_obi_apb_irq_spike.cpp` SHA256 为 `5ba38b648880ecd6d699fabe1dce5fe09a4a39a2ff2a69975c28b2ab18dfa743`，字段与地址由 `scripts/prepare_inprocess_irq_bindings.py` 从 profile 和 artifact 生成。直接循环仅支持同频单时钟和无内部定时事件的模型；其他情况明确拒绝。

在目标机 `/root/fanzehui/myfuzz-inprocess-irq-20261031` 中，源码、匹配原模型生成版本的 `include/`、由现有 F5 prefix 的 `program.images` 导出的 `firmware.txt` 已保存。`firmware.txt` SHA256 为 `6bdb1d0f77206df650049711b335f3bbc6ea09fc525d6e175dda07ba605bbdda`。原 prefix 在 `/root/fanzehui/myfuzz-stage2-prototype-20261031/runs/f5-single-summary2/prefix.json`，SHA256 为 `3db8b87ac671f0907d670980b9d2344147f6bf907af0e6e7c9c41e2296624308`。

构建和运行命令：

```sh
cd /root/fanzehui/myfuzz-inprocess-irq-20261031
c=/root/fanzehui/myfuzz-stage2-prototype-20261031/runs/cache-f5/dbf6c0c982420d0aaf2832dd4ecc68716b9beabd8b4bf4ac679c73211ad3af8c/obj
t=/root/fanzehui/myfuzz-stage2-prototype-20261031/runs/cache-f5/028d3b85e2e7f090dc5c18f1539cc03e6d6d458fbcc7f208e542589d3056b8d1/obj
root=/root/fanzehui/myfuzz-stage2-prototype-20261031
python3 prepare_inprocess_irq_bindings.py --root "$root" \
  --config "$root/runs/f5-single-summary2/config.json" \
  --prefix "$root/runs/f5-single-summary2/prefix.json" \
  --cpu-artifact "$c/../inputs/generated/artifact.json" \
  --ip-artifact "$t/../inputs/generated/artifact.json" --output .
/usr/bin/time -p g++ -std=c++17 -O2 -I. -I"$c" -I"$t" -Iinclude -Iinclude/vltstd \
  inprocess_obi_apb_irq_spike.cpp "$c/Vlocal_runtime_cpu__ALL.a" \
  "$t/Vlocal_runtime_pulp_timer_active__ALL.a" include/verilated.cpp \
  include/verilated_threads.cpp -pthread -latomic -o irq-spike
/usr/bin/time -p -o run.time ./irq-spike firmware.txt > run.log
cat run.log run.time
```

CPU 模型 archive SHA256 `f8abdac7e9d564efbd1d7eb92d2273ff7f1cb0615b5a48e914e1e7b85316fe64`；Timer 模型 archive SHA256 `ade19d6d6624eed0ad010edb5d9e53fac13db7beb15bd0c4662f6ba8eb868eb8`；旧固定绑定版可执行文件 SHA256 `1137894d5d5129129de3625a25d7a01315c196a309a35a416d605c9b7965bb54`，新生成绑定版 `fdcd09dd9aff44a77cd342aef98dd1ac78346a63dbe6875c6a751956803befdc`。这些 archive 来自原 source-locked F5 构建缓存，本记录的 archive 哈希是额外记录，不等于原构建 manifest 对 archive 的独立认证。

一次实际运行观测到 3 次 CPU MMIO 写及相应 APB 访问、Timer IRQ、CPU IRQ take、ISR 读 COUNT=0、RAM 结果写入、MRET 和后继退休，122 个宿主 tick，输出 `observations_passed`。旧固定绑定版程序自计 0.00568 秒、外层 wall 0.02 秒；新生成绑定版程序自计 0.00953 秒、外层 wall 0.03 秒；增加时钟检查的版本重跑自计 0.00783 秒。程序计时包括固件加载、模型构造、reset、执行和事件输出，不含程序退出及模型构建；新版本链接 11.25 秒，复用已有生成模型。该探索没有完整 F5 collector 和独立重放，调度及证据范围与既有多进程执行不同，不能据此计算严格加速比。

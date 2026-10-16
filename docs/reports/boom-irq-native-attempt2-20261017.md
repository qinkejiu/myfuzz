# BOOM IRQ 第二次真实运行：全局步数预算拒绝

实际 controller268173／gate268183 均终态 exit1。首次原生会话已运行，保存轨迹状态为 `budget_exhausted`，并非启动失败；fresh 和 IRQ 抑制负例尚未执行，整门未通过。

根代理独立复核[完整396文件归档](evidence/boom-irq-native-attempt2-20261017/evidence.tar.gz)、逐文件长度/SHA、前后源码/产物/工具映射及原始传输流。归档SHA为 `8e0a8f1e85e2e122ef052a83cd9d86fe46baea3f6c36926aa5a0ce3f6f671393`；[审计结果](evidence/boom-irq-native-attempt2-20261017/independent-audit.json)保留实际失败状态，不把轨迹改写成通过。2567个运行源码、2567个原来源文件和88个不可变产物均未变。

## 实际观察

CPU有两个真实进程：构造时启动检查268604和测量268732；GPIO进程268860。三个进程均关闭并exit0。测量轨迹包含2988个CPU样本、3012个GPIO样本、54452个Runner事件和6次实际路由交付。实际MEIP输入在CPU tick221至284为高，共64个tick；qualified MRET在429。轨迹保留实际trap及ISR／foreground存储。这些局部观察不代替完整fresh与抑制门。

最后事件精确为 `max_scheduler_steps`／`before_step`／`effect_may_have_occurred=false`，CPU2988＋GPIO3012＝6000。工厂请求6000次外层调度，再允许最多512次quiesce；Runner全局预算同时计算Router为实际APB访问额外执行的GPIO步数。因此原控制把主调度数当成全局上限，提前消耗了预算。

## 后续处理

已保留本次所有失败记录。下一源码修复明确使用原6000＋512＝6512的共享实际步数上限：间接GPIO步数也从同一额度扣除，quiesce最多512且仍受全局余额限制；不保证额外预留512步。主调度6000、IRQ64、固件和300秒墙钟上限均保持。修复须先通过软件回归和独立审查，再创建独立运行目录；本报告不声称新运行已发生。

整个系统与P6/P7/P8保持开放；无源权威或退休认证。

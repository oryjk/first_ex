# First / WeChatAppEx 适配文件

这里是维护源。当前保存 mac arm64 / WMPF 7.25755 已经打通的 hook.js 和 JSON。hook.js 与目前 /Applications/First.app 中的工作版本完全一致，本次没有改动其运行逻辑。Windows 目录暂为空，后续可以加入单独定位的配置；不能把 mac 偏移用于 Windows。

## 文件

```text
hook.js                         共享 Frida 脚本，需调试时在此修改
config/mac/addresses.25755.json  当前 mac 配置；新版本另存新文件，保留旧版
config/win/                     后续 Windows 配置
gen_wmpf_config.py               静态定位 mac/arm64 偏移，生成 JSON/证据
mac_scanner.py                   指令匹配、控制流和参数来源分析
install_first.py                校验、安装、备份和回滚
update_first.py                 串联生成与安装的 mac 入口
evidence/mac/                   每次生成的定位证据与适用限制
validation/mac/                 按 binary/hook/JSON 摘要绑定的运行验证记录
backups/generated/              本地生成文件的备份
backups/installed/              App 文件替换的备份
tests/                          误判及失败恢复的回归测试
```

Python 3.9+；mac 定位使用 Xcode Command Line Tools 的 lipo、xcrun/llvm-objdump。安装使用 Node.js --check 做语法检查（不执行 JS）。不依赖 Python Frida，也不会修改网络、微信签名或登录状态。

## 当前版本 / First 升级后恢复

在 Ghostty 执行：

```sh
cd ~/projects/first_ex
python3 install_first.py                # 预览，不修改 App
python3 install_first.py --apply        # 安装本地 hook 与 mac JSON
```

First 2 使用：

```sh
python3 install_first.py --app '/Applications/First 2.app' --apply
```

默认安装当前平台全部本地 JSON；--version 25755 可以只选择一个版本（可重复）。其他 App 中原有的 JSON 不会被删除。运行中的 First 需退出并重开以重新加载文件；安装成功只表示文件替换完成，不代表注入成功。

## 微信升级后的流程

1. 先定位候选，默认只输出、不写入：

```sh
python3 gen_wmpf_config.py
```

已经匹配二进制/脚本/JSON 的验证记录时，可直接写入本目录。未知二进制必须显式选择 CDP 策略，例如先测试原生 CDP：

```sh
python3 gen_wmpf_config.py --cdp-policy native --write
```

--write 只写 first_ex，不再直接写 App。如果必须修补 CDP，需人工确认目标函数语义，再使用 --cdp-filter-offset 0xADDRESS；共享 JSON 解析函数不能作为替代目标。

2. 定位失败、第三跳改变、字符串/ABI/流程改变时，先分析和修改本目录 hook.js / 定位器；不能给旧字段塞一个猜测地址绕过错误。脚本不会自动编写任意新版本的 hook.js，而是使用此处已经维护好的最新脚本。

3. 未验证的新配置需要显式试装：

```sh
python3 install_first.py --version NEW_VERSION --allow-unverified --apply
```

这表示“允许用于调试”，不会把配置标记为已经验证。整个 mac 流程也可串成一个命令：

```sh
python3 update_first.py --cdp-policy native --allow-unverified --apply
```

此命令先生成本地 JSON/证据，再使用本地 hook.js 安装。生成失败立即停止。已验证版本可以运行 python3 update_first.py --apply；不带 --apply 时会生成本地文件并预览安装。

4. 重启 First，启动注入，重新打开目标小程序。至少验证页面正常、Runtime.evaluate('1+1') 返回 2、Debugger.getScriptSource 能读取真实 app-service.js，再在独立重启后复查。此前已记录的 25755 运行证据见 validation/mac 对应文件的 evidence_files。

5. 完成验证后，由实际执行验证的人/agent 更新 validation：runtime_verified、binary_sha256（arm64 slice）、hook_sha256、config_sha256，附测试时间、真实目标与验证记录路径。不能仅因为静态定位成功就改成 true。hook 或 JSON 变化会使原验证记录失效；旧版本应按实际支持列表回归。

## 回滚

安装产生独立时间戳备份，并打印其路径。退出 First 后执行：

```sh
python3 install_first.py --rollback ~/projects/first_ex/backups/installed/BACKUP_ID
python3 install_first.py --rollback ~/projects/first_ex/backups/installed/BACKUP_ID --apply
```

指定 First 2 或其他资源目录时，回滚也必须指定同一个 --app / --resources。回滚会恢复旧文件并移除当次新增的配置；如果目标后来被修改，拒绝覆盖，需人工检查。

单个文件采用完整写入并 fsync 后原子替换。多个文件中途失败会恢复已替换的文件；进程被强制终止时，可根据 prepared 状态的备份恢复。不要在安装期间让其他程序同时改这些文件。

## Windows

当前没有 Windows 偏移生成器，也没有 Windows 运行验证。安装逻辑已用临时目录验证，支持 First 原生顶层格式（Version、LoadStartHookOffset、SceneOffsets）及 Arch 格式。

将配置放到 config/win，Windows 上安装时用实际的资源目录（其中必须存在 frida/hook.js）：

```sh
python install_first.py --platform win --resources 'C:\path\to\First\resources' --allow-unverified --apply
```

上面的路径是占位符，要按实际安装结构填写。不要默认它一定叫 resources。

## 能覆盖哪些升级

适配文件通常是 hook.js + 对应版本/架构的 JSON；地址、结构偏移的变动尽量放进 JSON。引擎流程、字符串格式、调用约定变化需要调试 JS；Frida、注入权限/签名、模块加载或 First 的协议代理变化，也可能需要文件之外的处理。因此不能承诺“每次升级运行脚本就一定打通”。

当前静态定位器只识别相邻 ADRP+ADD、特定三跳守卫、libc++ alternate 字符串模式，入口回溯和控制流有明确窗口。匹配不到或有多个候选会停止，这是适用边界，不是适配完成。

## 验证

```sh
python3 -m unittest discover -s tests -v
node --check hook.js
```

已测试误字符串引用、相邻函数、多个候选、参数来源、第三/第四跳、非零 Mach-O vmaddr、未知 CDP 策略、非法 JSON/JS、失败恢复与回滚。未测试其他实际微信版本或 Windows 注入。

旧的 ~/Documents/wmpf-first-25755/gen_wmpf_config.py 已改为调用这里的兼容入口；原始实现另有备份。以后只维护本目录。

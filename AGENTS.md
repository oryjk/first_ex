# First 适配维护

- 用简体中文沟通；本目录是适配文件的唯一维护源，不直接编辑 App 内文件。
- hook.js 是共享脚本；保持旧字段默认行为与 Windows 分支。修改后旧版本兼容性需要按支持列表回归，不能只靠参数默认值宣称兼容。
- config/mac/addresses.VERSION.json 使用 Arch；config/win 同时支持原生顶层格式与 Arch 格式。不要用 mac 偏移生成 Windows 配置。
- gen_wmpf_config.py 仅支持 mac arm64 的已声明模式，无法识别时停止；不要添加未验证的猜测值兜底。
- 不修改网络、代理、DNS、路由、VPN、SIP、签名；这些属于独立诊断。
- 当前用户明确限制（2026-10-22）：后续适配只调整 First 的 Frida 依赖、hook 脚本及偏移配置；不重签微信，不修改微信本体或系统保护设置。此前的重签名和中途快照恢复是历史试验，不是后续操作授权。微信原始文件已恢复；优先排查正常登录问题，不再激活这些试验快照。
- validation 中 runtime_verified=true 必须有实际运行证据，并绑定当前二进制、hook、JSON SHA256；只连上 WebSocket 或看到 ready 不算打通。
- 至少验证 Runtime.evaluate 返回 2、实际 app-service.js 源码可读、小程序页面正常；独立重启后再确认，不在 DevTools 内用 ⌘R 重载小程序。
- 修改生成器/安装器后运行 python3 -m unittest discover -s tests -v；安装前预览，失败保留备份与错误。

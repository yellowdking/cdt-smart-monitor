# CDT Smart Monitor

基于阿里云国际站（200GB 免费 CDT 流量 + $0.50 抹零规则）场景重构的轻量化多机智能轮换与双阈值风控控制台。采用纯 Go 1.24 标准库实现（零第三方依赖），单容器开箱即用。

## 核心特性
- **双维度自定义熔断**：支持每台机器独立自定义流量上限（默认 200GB）与金额上限（默认 $0.50）；底层内置 30GB 流量安全垫与 $0.05 金额安全垫，无需手动配置复杂缓冲。
- **两次刷新差值急停与高峰优先级**：非高峰相邻两次刷新流量增幅 > 30GB 或全时段费用增幅 > $0.05 立即停机切换；高峰期「单班突发上限」优先级高于全局 30GB 差值限制，保障高峰稳定运行。
- **动态智能轮换（最低 2 台起步）**：非使用时段全池集体节省停机（`StopCharging`）；高峰期按池内健康机器数自动均分时段，支持按日自动互换槽位及余量差 ≥ 20% 时自动纠偏顶班，正常换班采用先开后关（Make-Before-Break）。
- **抢占式实例保活**：支持单机与轮换池内抢占式实例自动拉起，连续 3 次拉起失败自动故障转移至备机（阈值熔断与闲时关机优先于保活）。
- **通知代理与安全认证**：支持 Telegram / Webhook 通知、HTTP/HTTPS/SOCKS5 代理、自定义 Telegram 反代地址与实时测试；内置首次安全初始化、本地管理员密码（PBKDF2-HMAC-SHA256）、IP 登录限速以及 HTTPS WebAuthn Passkey 通行密钥。

## 快速部署（Docker Compose）
```bash
git clone [https://github.com/yellowdking/cdt-smart-monitor.git](https://github.com/yellowdking/cdt-smart-monitor.git) && cd cdt-smart-monitor
docker compose up -d --build
```
启动后浏览器访问 `http://服务器IP:43211` 完成首次管理员密码初始化即可使用（公网部署建议通过 Nginx / Caddy 反代启用 HTTPS 并透传 `Host` 与 `X-Forwarded-Proto: https`，以开启 Passkey 通行密钥保护）。

## 致谢与开源协议
- 本项目的产品思路、阿里云 CDT/ECS/BSS 监控架构与核心场景参考自开源项目 [wang4386/CDT-Monitor](https://github.com/wang4386/CDT-Monitor)（MIT License），在此向原作者及社区贡献者致以诚挚感谢！
- 本项目采用 [MIT License](LICENSE) 开源。

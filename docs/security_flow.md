\section{TSC-VEE 安全通信流程}

TSC-VEE 实现了完整的双向加密通信机制，确保智能合约的字节码和执行结果在传输过程中的安全性。整个过程分为两个主要阶段：合约输入加密传输和执行结果加密返回。

\subsection{合约输入安全传输 (Host → TA)}

1. Host 端加密准备
   - 从环境变量或配置文件加载私钥（TSC_PRIVKEY）
   - 使用 BLAKE2b（crypto_generichash）从私钥派生 32 字节密钥
   - 初始化 libsodium AES-256-GCM 加密模块

2. Bytecode 加密
   - 生成 12 字节随机 nonce
   - 使用 AES-256-GCM 加密 bytecode 字符串
   - 加密数据格式：`[nonce][encrypted_bytecode+tag]`
     * nonce: 12 字节随机数
     * encrypted_bytecode: AES-GCM 加密后的字节码
     * tag: 16 字节认证标签

3. 分块传输加密数据
   - 初始化传输：发送总大小信息
   - 将加密数据分块（每块最大 8192 字节）
   - 通过 TEEC_InvokeCommand 逐块发送

4. TA 端解密处理
   - 接收并重组完整的加密数据
   - 提取 nonce 和加密内容
   - 使用相同的派生密钥进行解密
   - 验证 GCM 认证标签
   - 解密成功后进行字节码解析和执行

\subsection{执行结果安全返回 (TA → Host)}

1. TA 内部输出加密
   - 生成标准格式的执行结果：
```
Result: <status_code>
Gas used: <gas_used>
Output: <hex_output>
```
   - 使用与解密 bytecode 相同的密钥进行 AES-256-GCM 加密
   - 加密输出格式：`[nonce][encrypted_output+tag]`
   - 加密后的数据存储在 output_buffer 中

2. 分块传输机制
   - 使用 get_output 命令分两个阶段传输：
     * 首先获取加密输出的总大小
     * 然后分块传输加密数据，每块最大 8192 字节

3. Host 端解密处理
   - 在 receive_output_from_ta 函数中：
     * 完整接收所有加密数据块
     * 提取 nonce 和加密内容
     * 使用相同的密钥进行解密
     * 验证认证标签确保数据完整性
   - 解密成功后还原为标准格式输出

\subsection{安全保证}

整个双向加密通信机制提供以下安全保证：

1. 机密性保护
   - 使用 AES-256-GCM 加密所有敏感数据
   - 合约字节码在传输过程中受到保护
   - 执行结果在返回过程中受到保护

2. 完整性保证
   - GCM 认证标签确保数据未被篡改
   - 分块传输过程中保持数据完整性
   - 密文与认证标签绑定

3. 防重放保护
   - 每次加密使用随机生成的 nonce
   - 双向通信均使用不同的 nonce

4. 密钥管理
   - Host 与 TA 使用相同的密钥派生方法
   - 支持通过环境变量动态配置密钥
   - 密钥派生使用安全的 BLAKE2b 哈希函数

5. 错误处理
   - 加密失败时安全清理内存
   - 解密失败时提供明确的错误信息
   - 内存分配失败时的安全回退机制

这种双向加密机制确保了智能合约在 TSC-VEE 中的执行过程完全处于加密保护之下，从合约部署到结果返回的整个生命周期都得到了安全保障。
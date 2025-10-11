为了让**内网穿透功能能够正常工作，您必须**修改您的**远程SSH服务器**的配置文件。

1. 登录到您的远程SSH服务器。

2. 使用 `root` 权限编辑 SSH 配置文件：

   ```
   sudo vim /etc/ssh/sshd_config
   ```

3. 确保文件中有以下**两行**配置，并且它们没有被 `#` 注释掉：

   ```
   # 这是所有端口转发功能的总开关，必须为 yes
   AllowTcpForwarding yes
   
   # 这允许反向隧道的端口被公网访问，必须为 yes
   GatewayPorts yes
   ```

4. 保存文件后，**重启SSH服务**以使配置生效：

   ```
   sudo systemctl restart sshd
   ```

并且 , 开启对应端口的防火墙
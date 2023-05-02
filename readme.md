## ZxwyWebSite/NgConf
### 简介
+ 为海纳思系统的Nginx开发的一键配置工具
+ **※其它系统可能不兼容，支持在配置文件修改路径**
+ 模板参考宝塔面板的配置

### 使用
+ 运行 `./ngconf`
+ 根据提示输入网站信息，即可自动生成站点

### 卸载
+ 所有数据保存在程序目录，使用软链接映射到nginx目录
+ 卸载时请使用 `./ngconf uninstall`，可以自动清理nginx目录残留

### 其它
+ 暂不支持一键配置SSL，请手动申请证书
+ 输入信息暂无验证，请按照标准格式填写

### 更新
#### 2023-05-02 v1.0
+ 配置文件相关的暂未写好，已注释掉
+ 当前仅可在海纳思系统使用，暂不挂到主页
+ 没有错误处理，请严格按照提示填写
+ 数组限制，暂时只能创建20个网站
+ 所有配置保存在程序目录，请先确定好位置，添加站点后就不要轻易挪位置了

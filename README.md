# java

1.该项目为单点登录客户端jar包 cas-client-core源文件，基于cas-client-core-3.2.1；

2.为实现内外网登录可使用同一服务，修改cas客户端源代码：
	①.客户端服务器web.xml中同时配置内外网地址；
	②.在filter中加入对网段的判断，如果是内网，则跳转至内网地址，否则跳至外网地址

3.主要修改代码如下：
	①：authentication/AuthenticationFilter.java中dofilter加入全局isInnerNet，判断是否内网地址；
	②：util、CommonUtils.java等多处代码 中对web.xml中读取的内外网地址根据①的判断进行过滤。

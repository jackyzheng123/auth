# Auth Demo
这是一个简单的使用Spring Boot，Spring Security和JWT做RESTful API的登陆鉴权Demo。

启动项目后，浏览器打开http://localhost:8080/swagger-ui.html查看接口。

项目启动前需要配置数据库，在数据库中创建名为auth的数据库。IDE需要安装lombok插件。



##主要看点：
####1.登陆后获取token，根据token来请求资源
####2.根据用户角色来确定对资源的访问权限
####3.统一异常处理
####4.返回标准的Json格式数据



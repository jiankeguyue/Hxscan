## 0x01 Hxscan工具功能介绍

- 支持 http/https 自主判断
- 聚合 ehole指纹 wapplyzer指纹一体化
- 获取title，自动验重
- js跳转获取最终页面 ，比如maxview/manager/login.xhtml
- favicon 自动分析获取 iconhash，比如maxview/manager/login.xhtml



## 0x02 研发过程

CMS指纹采取json方式读取，分header，body，faviconhash三种种类，其中faviconhash采用的是mmh32hash，body分title和body两种

![image-20240402212907762](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402212907762.png)

中间件指纹接的是wapplyzer的接口

![image-20240402213157841](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402213157841.png)

title获取采用了dom节点树和关键词获取法(dom节点老是很难获取成功)

![image-20240402213248603](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402213248603.png)

很多网页采用了js自动跳转，这里采用正则截取跳转，并拼接url进行访问

![image-20240402213401778](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402213401778.png)

favicon同样采取dom节点提取和正则匹配获取

![image-20240402213809854](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402213809854.png)





开发环境

```
go version go1.21.6 windows/amd64
```

测试环境

![image-20240402215336063](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402215336063.png)

```
go version go1.21.6 windows/amd64
```



## 0x03 效果展示

![image-20240402222056897](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402222056897.png)

![image-20240402222142800](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402222142800.png)

![image-20240402213936143](https://gitee.com/yuejinjianke/tuchuang/raw/master/image/image-20240402213936143.png)

若为了方便处理站点，进行后续的poc测试和去重，可采用以下语法

```
 ./Hxscan.exe sitescan -f 1.txt -o 2.txt --no-color  
```

目前只支持sitescan站点扫描，后续版本会增设更多功能



最后，感谢以下项目的贡献者

```
https://github.com/projectdiscovery/naabu
https://github.com/EdgeSecurityTeam/EHole/
```


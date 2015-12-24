###测试Android页面重复率
---
<br>
#####测试平台
* 系统：Android-6.0
* 内核版本：4.0.9
* 平台：x86_64
* CPU：双核
* 内存：2 GB

<br>

#####刚开机时的页面重复率
1.启动Android虚拟机，进入桌面后，按下`Alt+F1`进入终端，执行`free -m`命令，查看内存使用情况：

> 
mem   `total: 2005mb`  `used: 777mb`  `free: 1227mb` 

2.执行`insmod ycache.ko`加载模块，执行`echo 1 > /proc/sys/vm/drop_caches`，
再查看ycache模块的debugfs输出，部分参数如下：

>第一次：
<br>total_pages: 34055
<br>used_pages: 33753
<br>obj_count: 889
<br>objnode_count: 2394
<br>
<br>第二次(关机后重启再测得）：
<br>total_pages: 36544
<br>used_pages: 36164
<br>obj_count: 889
<br>objnode_count: 2418

3.计算页面重复率为：

> 
`1 - 33753/34055 = 1 - 99.11% = `**0.89%**<br>
`1 - 36164/36544 = 1 - 98.96% = `**1.04%**


<br>
####下面对应用场景进行测试
---
#####前期准备
从官网下载QQ、UC浏览器、WPS等应用，使用adb push到Android虚拟机中进行安装（目前在Android-x86上，微信不能运行；WPS、Adobe Acrobat不能阅读PDF）。
<br>


#####使用WPS时的页面重复率
1.启动Android虚拟机，进入桌面后，按下`Alt+F1`进入终端，执行`free -m`命令，查看内存使用情况：

> 
mem   `total: 2005mb`  `used: 850mb`  `free: 1154mb` 

2.执行`insmod ycache.ko`加载模块，执行`echo 1 > /proc/sys/vm/drop_caches`，再查看ycache模块的debugfs输出，部分参数如下：

>total_pages: 46936
<br>used_pages: 46447
<br>obj_count: 940
<br>objnode_count: 2717
<br>flush_obj_found: 0
<br>flush_page_found: 0
<br>hash_collision: 0
<br>put_to_flush: 0
<br> `1 - 46447/46936 = 1 - 98.958% = `**1.042%**

3.按`Alt+F7`进入图形界面，启动WPS，进入终端界面，执行`echo 1 > /proc/sys/vm/drop_caches`，再查看ycache模块的debugfs输出，部分参数如下：

>total_pages: 47884
<br>used_pages: 47388
<br>obj_count: 955
<br>objnode_count: 2761
<br>flush_obj_found: 0
<br>flush_page_found: 0
<br>hash_collision: 0
<br>put_to_flush: 0
<br> `1 - 47388/47884 = 1 - 98.964% = `**1.036%**

4.打开一些Word、PPT文件（不同，一共20MB左右），正常使用一段时间。进入终端界面，执行`echo 1 > /proc/sys/vm/drop_caches`，再查看ycache模块的debugfs输出，部分参数如下：

>total_pages: 48996
<br>used_pages: 48557
<br>obj_count: 943
<br>objnode_count: 2878
<br>flush_obj_found: 4
<br>flush_page_found: 6
<br>hash_collision: 0
<br>put_to_flush: 0
<br> `1 - 48557/48996 = 1 - 99.104% = `**0.896%**

5.将其中一个PPT文件（16M左右）进行6次另存为不同文件名，再同时打开这7个相同文件文件，来回切换，确认都能正常打开，
并进行播放。进入终端界面，执行`free -m`命令，查看内存使用情况：

> 
mem   `total: 2005mb`  `used: 1558mb`  `free: 446mb` 


执行`echo 1 > /proc/sys/vm/drop_caches`，再查看ycache模块的debugfs输出，部分参数如下：

>total_pages: 54636
<br>used_pages: 52920
<br>obj_count: 961
<br>objnode_count: 2916
<br>flush_obj_found: 6
<br>flush_page_found: 70
<br>hash_collision: 0
<br>put_to_flush: 0
<br> `1 - 52920/54636 = 1 - 96.859% = `**3.141%**

执行`free -m`命令，查看内存使用情况：

> 
mem   `total: 2005mb`  `used: 1163mb`  `free: 841mb` 
##测试单CPU不同Hash函数下ycache性能指标

测试结果
---

| 测试项目    |md5 视频文件  | md5 全0文件  |sha1 视频文件 |sha1 全0文件  |
| ----------- |--------------|--------------|--------------|--------------|
| 入模块      | 375MB/s      | 382MB/s      |351MB/s       |359MB/s       |
| 读取重复    | 1.6GB/s      | 2.0GB/s      |1.4GB/s       |1.9GB/s       |
| 读取唯一    | 1.2GB/s      | 1.9GB/s      |1.2GB/s       |1.8GB/s       |

<br>
测试步骤
---


#####测试sha1下ycache性能


######使用两个相同的100MB视频文件
1. 开机，执行`watch free -h`，监控可用内存和缓存大小。
   执行`echo 1 > /proc/sys/vm/drop_caches`，将缓存drop掉
   
2. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，加载100MB的视频文件，从机械硬盘读取，速率为`82.2MB/s`，
   再执行一次，从缓存中读取，速率为`4.8GB/s`
   
3. 执行`insmod ycache.ko`加载模块，此时缓存大小为178MB。
   执行`time echo 1 > /proc/sys/vm/drop_caches`后，缓存大小为82MB。
   测得时间：`real:0.292s   user:0.000s   sys:0.274s`。
   则入模块速率为 `(178-82)/0.274 = `**350 MB/s**
   
4. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，把1.mov从模块取出来，速率为1.2GB/s。
   再执行`dd if=2.mov of=/dev/null bs=1MB count=100`，把2.mov加载到缓存(与1.mov一样）
   
5. 此时缓存大小为273MB，执行`time echo 1 > /proc/sys/vm/drop_caches`，缓存大小为79MB
   测得时间：`real:0.577s   user:0.000s   sys:0.543s`。
   则入模块速率为 `(273-82)/0.543 = 351 MB/s`
   
6. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，速率为**1.4GB/s**。
   再执行`dd if=2.mov of=/dev/null bs=1MB count=100`，速率为**1.2GB/s**。
   由此得到结果如下
   
* 入模块：351MB/s             
* 读取重复：1.4GB/s             
* 读取唯一：1.2GB/s 

<br>

######使用两个相同的100MB全零文件
1. 开机，执行`watch free -h`，监控可用内存和缓存大小。
   执行`echo 1 > /proc/sys/vm/drop_caches`，将缓存drop掉
   
2.执行`dd if=z1 of=/dev/null bs=1MB count=100`，加载100MB的全0文件
（由`dd if=/dev/zero of=z1 bs=1MB count=100`生成），从机械硬盘读取，速率为`77.4MB/s`，
   再执行一次，从缓存中读取，速率为`5.1GB/s`
   
3. 执行`insmod ycache.ko`加载模块，此时缓存大小为169MB。
   执行`time echo 1 > /proc/sys/vm/drop_caches`后，缓存大小为73MB。
   测得时间：`real:0.291s   user:0.000s   sys:0.273s`。
   则入模块速率为 `(169-73)/0.273 = `**351 MB/s**
   
4. 执行`dd if=z1 of=/dev/null bs=1MB count=100`，把z1从模块取出来，速率为1.8GB/s。
   再执行`dd if=z2 of=/dev/null bs=1MB count=100`，把z2加载到缓存(与z1一样）
   
5. 此时缓存大小为264MB，执行`time echo 1 > /proc/sys/vm/drop_caches`，缓存大小为73MB。
   测得时间：`real:0.566s   user:0.000s   sys:0.532s`。
   则入模块速率为 `(264-73)/0.532= 359 MB/s`
   
6. 执行`dd if=z1 of=/dev/null bs=1MB count=100`，速率为**1.9GB/s**。
   再执行`dd if=z2 of=/dev/null bs=1MB count=100`，速率为**1.8GB/s**。
   由此得到结果如下
   
* 入模块：359MB/s             
* 读取重复：1.9GB/s             
* 读取唯一：1.8GB/s 

<br>
<br>

#####测试md5下ycache性能

<br>

######使用两个相同的100MB视频文件
1. 开机，执行`watch free -h`，监控可用内存和缓存大小。
   执行`echo 1 > /proc/sys/vm/drop_caches`，将缓存drop掉
   
2. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，加载100MB的视频文件，从机械硬盘读取，速率为`81.1MB/s`，
   再执行一次，从缓存中读取，速率为`4.9GB/s`
   
3. 执行`insmod ycache.ko`加载模块，此时缓存大小为174MB。
   执行`time echo 1 > /proc/sys/vm/drop_caches`后，缓存大小为79MB。
   测得时间：`real:0.273s   user:0.000s   sys:0.261s`。
   则入模块速率为 `(174-79)/0.261 = `**363 MB/s**
   
4. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，把1.mov从模块取出来，速率为1.2GB/s。
   再执行`dd if=2.mov of=/dev/null bs=1MB count=100`，把2.mov加载到缓存(与1.mov一样）
   
5. 此时缓存大小为270MB，执行`time echo 1 > /proc/sys/vm/drop_caches`，缓存大小为79MB。
   测得时间：`real:0.537s   user:0.000s   sys:0.508s`。
   则入模块速率为 `(270-79)/0.508 = 375 MB/s`
   
6. 执行`dd if=1.mov of=/dev/null bs=1MB count=100`，速率为**1.6GB/s**。
   再执行`dd if=2.mov of=/dev/null bs=1MB count=100`，速率为**1.2GB/s**。
   由此得到结果如下
   
* 入模块：375MB/s             
* 读取重复：1.6GB/s             
* 读取唯一：1.2GB/s             
   
<br>

######使用由五个100MB视频文件通过cat连接成的文件
1. 开机，执行`watch free -h`，监控可用内存和缓存大小。
   执行`echo 1 > /proc/sys/vm/drop_caches`，将缓存drop掉
   
2. 执行`dd if=5same.mov of=/dev/null bs=1MB count=500`，加载500MB的视频文件，从机械硬盘读取，速率为`82.9MB/s`，
   再执行一次，从缓存中读取，速率为`4.7GB/s`
   
3. 执行`insmod ycache.ko`加载模块，此时缓存大小为555MB。
   执行`time echo 1 > /proc/sys/vm/drop_caches`后，缓存大小为78MB。
   测得时间：`real:1.334s   user:0.000s   sys:1.256s`。
   则入模块速率为 `(555-78)/1.256 = `**380 MB/s**
   
4. 执行`dd if=5same.mov of=/dev/null bs=1MB count=500`，把1.mov从模块取出来，速率为**1.4GB/s**。

<br>

######使用两个相同的100MB全零文件
1. 开机，执行`watch free -h`，监控可用内存和缓存大小。
   执行`echo 1 > /proc/sys/vm/drop_caches`，将缓存drop掉
   
2. 执行`dd if=z1 of=/dev/null bs=1MB count=100`，加载100MB的全0文件
（由`dd if=/dev/zero of=z1 bs=1MB count=100`生成），从机械硬盘读取，速率为`76.8MB/s`，
   再执行一次，从缓存中读取，速率为`5.1GB/s`
   
3. 执行`insmod ycache.ko`加载模块，此时缓存大小为221MB。
   执行`time echo 1 > /proc/sys/vm/drop_caches`后，缓存大小为124MB。
   测得时间：`real:0.280s   user:0.000s   sys:0.266s`。
   则入模块速率为 `(221-124)/0.266 = `**364 MB/s**
   
4. 执行`dd if=z1 of=/dev/null bs=1MB count=100`，把z1从模块取出来，速率为1.7GB/s。
   再执行`dd if=z2 of=/dev/null bs=1MB count=100`，把z2加载到缓存(与z1一样）
   
5. 此时缓存大小为315MB，执行`time echo 1 > /proc/sys/vm/drop_caches`，缓存大小为124MB。
   测得时间：`real:0.527s   user:0.000s   sys:0.499s`。
   则入模块速率为 `(315-124)/0.499 = 382 MB/s`
   
6. 执行`dd if=z1 of=/dev/null bs=1MB count=100`，速率为**2.0GB/s**。
   再执行`dd if=z2 of=/dev/null bs=1MB count=100`，速率为**1.9GB/s**。
   由此得到结果如下
   
* 入模块：382MB/s             
* 读取重复：2.0GB/s             
* 读取唯一：1.9GB/s  






DomainCertMonitor支持自动拉取阿里云和腾讯云域名进行TLS证书探测，并借助于Blackbox exporter告警和展示证书到期时间等。另外也支持手动添加域名进行TLS证书探测和告警。

# 一、基础环境
1、代理设置
推荐使用腾讯云镜像加速下载（Windows）：
> set GOPROXY=https://mirrors.tencent.com/go/

1、腾讯云SDK
> go get -v -u github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common
> go get -v -u github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323


2、阿里云SDK
> go get -v -u github.com/alibabacloud-go/darabonba-openapi/client                                                                                                            
> go get -v -u github.com/alibabacloud-go/alidns-20150109/v2/client

3、其它包
> go get -v -u github.com/spf13/viper


# 二、配置文件
1、配置文件修改
> vi config/config.yml
key:
  cipher_key: "加密解密的key"
cloud:
  alibaba:
    aliyun_key: "阿里云AK"
    aliyun_secret: "阿里云AS"
    region: "cn-shenzhen"
  tencent:
    tencent_key: "腾讯云KEY"
    tencent_secret: "阿里云密钥"
api:
  wx_api: "企业微信机器人"
  alarmcore_api: "内部告警平台"
  prometheus_api: "http://127.0.0.1:9090/-/reload"
file:
  blackbox_path: "/opt/prometheus/blackbox/http/aliyun-tencent-httpsdomain.yml"
  labels_web: "web"
  labels_department: "test-auto"
manual:
  expire_day: 15
  domain_list:
    - mqtt.test.com
    - office.test.net:6443

# 三、运行打包
1、运行
> go run .\domain_cert_monitor.go

2、打包
> go env -w CGO_ENABLED=0 GOOS=linux GOARCH=amd64
> go build -o domain_cert_monitor .\domain_cert_monitor.go

Linux下运行
$ cd /opt/script/domain_cert_monitor
$ .\domain_cert_monitor


# 四、生产部署
1、prometheus相关配置文件
（1）blackbox-exporter配置文件
$ cat /opt/blackbox_exporter/blackbox.yml
modules:
  http_2xx:
    prober: http
  http_post_2xx:
    prober: http
    http:
      method: POST
  https_domain:
    prober: http
    timeout: 5s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: [200, 301, 302, 400, 401, 403, 500, 502, 503]
  ……
  
（2）prometheus配置文件
$ cat /opt/prometheus/prometheus.yml
- job_name: aliyun-tencent-httpsdomain
    scrape_interval: 300s
    metrics_path: /probe
    params:
      module: [https_domain]
    file_sd_configs:
    - refresh_interval: 1m
      files:
      - blackbox/http/aliyun-tencent-httpsdomain.yml
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 172.20.15.13:9115

2、定时任务
$ cd /opt/script/domain_cert_monitor
$ crontab -l
30 10 * * * cd /opt/script/domain_cert_monitor && ./domain_cert_monitor

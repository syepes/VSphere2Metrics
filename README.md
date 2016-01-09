vSphere2Metrics
================
---
vSphere2Metrics is a performance metric collector for [vSphere](https://www.vmware.com/products/vsphere) that supports [Graphite](http://graphite.wikidot.com/) and [InfluxDB](https://influxdata.com/time-series-platform/influxdb/) as its storage engines.

Essentially is gathers all the raw 20 second performance metrics from every the Hosts and VM’s registered in the vSphere.
Once the metrics have been collected and stored in your preferred storage engine there is no limits to which kind of performance analytics and dashboards you can construct.


A Brief Overview  of how vSphere2Metrics works:

    - Parallely connects to each of the specified vSphere servers (vcs.urls)
    - Gathers the last events and performance metrics samples (vcs.perf_max_samples) of all the registered Hosts and VMs
    - Constructs the according Graphite or InfluxDB metrics
    - Sends the previously built and buffered metrics using MetricClient (destination.type)
    - If it fails, metrics get buffered until the next run, if not it just sleeps until the next execution (vcs.perf_max_samples)
    - The process start all over again


## Features
- Collects all [available metrics](http://pubs.vmware.com/vsphere-60/index.jsp#com.vmware.wssdk.apiref.doc/vim.PerformanceManager.html) concurrently ([GPars](http://gpars.codehaus.org))
- Metrics are buffered if the storage engines is down ([MetricClient](https://github.com/syepes/MetricClient))
- Supports Graphite Standard mode (UnCompressed) or Pickle (Serializing)
- Supports InfluxDB HTTP UnCompressed or Compresses Line Protocol
- Continues collection mode (daemon) or one shoot command line.
- Supports vSphere 4.x, 5.x and 6.0

### Examples
![Perf Global](https://raw.githubusercontent.com/syepes/vSphere2Metrics/gh-pages/images/PerfGlobal.png)
![Perf ESXi](https://raw.githubusercontent.com/syepes/vSphere2Metrics/gh-pages/images/PerfESXi.png)


## Requirements
- [Java](http://www.java.com) 1.7+
- [Gradle](http://www.gradle.org) (Only if building the project from src)

## Installation and Configuration
Take a look at the vSphere2Metrics [Wiki](https://github.com/syepes/vSphere2Metrics/wiki)

## Contribute
If you have any idea for an improvement or find a bug do not hesitate in opening an issue.
And if you have the time clone this repo and submit a pull request to help improve the vSphere2Metrics project.

## License
vSphere2Metrics is distributed under [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

Copyright &copy; 2016, [Sebastian YEPES F.](mailto:syepes@gmail.com)

## Used open source projects
[Groovy](http://groovy.codehaus.org) |
[GPars](http://gpars.codehaus.org) |
[Logback](http://logback.qos.ch) |
[vijava](http://www.doublecloud.net/product/vijavang.php) |
[MetricClient](https://github.com/syepes/MetricClient)

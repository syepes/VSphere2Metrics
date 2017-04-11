vSphere2Metrics
================
---
vSphere2Metrics is a performance metric collector for [vSphere](https://www.vmware.com/products/vsphere) that supports [Graphite](http://graphite.wikidot.com/) and [InfluxDB](https://influxdata.com/time-series-platform/influxdb/) as its storage engine.

The main idea behind this project compared to others out there is, collect all and analyse later.

So it gathers all the available 20 second raw performance metrics of every the Hosts, VM's and VSAN that are registered in the vSphere.<br />
Once the metrics have been collected and stored in your preferred storage engine there is no limits to which kind of performance analytics and dashboards you can construct.


A brief overview of how vSphere2Metrics works:

    - Simultaneously connects to each of the specified vSphere servers (vcs.urls)
    - Gathers the events and performance metrics samples (vcs.perf_max_samples) from the last successfully collected timestamp
    - Constructs the according Graphite or InfluxDB metrics
    - Sends the previously built and buffered metrics using MetricClient (destination.type)
    - If it fails, metrics get buffered until the next run, if not it just sleeps until the next execution (vcs.perf_max_samples)
    - The process starts all over again


## Features
- Connects to each vSphere concurrently ([GPars](http://gpars.codehaus.org))
- Collects all raw metrics from HostSystem, ResourcePool (QuickStats), VirtualMachine and VSAN Statistics
- Metrics are buffered if the storage engine is down ([MetricClient](https://github.com/syepes/MetricClient))
- Supports Graphite Standard mode (UnCompressed) or Pickle (Serializing)
- Supports InfluxDB HTTP UnCompressed or Compresses Line Protocol
- Continues collection mode (daemon) or one shoot command line.
- Supports vSphere 4.x, 5.x and 6.x

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

Copyright &copy; 2017, [Sebastian YEPES F.](mailto:syepes@gmail.com)

## Used open source projects
[Groovy](http://groovy.codehaus.org) |
[GPars](http://gpars.codehaus.org) |
[Logback](http://logback.qos.ch) |
[yavijava](http://www.yavijava.com) |
[MetricClient](https://github.com/syepes/MetricClient)

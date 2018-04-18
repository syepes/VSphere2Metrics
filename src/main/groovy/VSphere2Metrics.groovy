/**
 *
 * @author Sebastian YEPES FERNANDEZ (syepes@gmail.com)
 */

package com.allthingsmonitoring.vmware

import org.slf4j.*
import groovy.util.logging.Slf4j
import ch.qos.logback.classic.*
import static ch.qos.logback.classic.Level.*
import org.codehaus.groovy.runtime.StackTraceUtils
import groovyx.gpars.GParsPool
import groovyx.gpars.util.PoolUtils
import groovy.json.JsonSlurper
import groovy.json.internal.LazyMap

import com.xlson.groovycsv.CsvParser
import java.util.regex.Matcher
import java.util.zip.*
import java.util.jar.Manifest
import java.util.jar.Attributes

import groovy.transform.TimedInterrupt
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

import groovy.time.*
import java.text.SimpleDateFormat

import java.net.URL
import java.net.HttpURLConnection
import com.vmware.vim25.*
import com.vmware.vim25.mo.*

import java.rmi.RemoteException
import java.net.MalformedURLException

import java.security.MessageDigest
import javax.crypto.*
import javax.crypto.spec.*

import com.allthingsmonitoring.utils.MetricClient


@Slf4j
class VSphere2Metrics {
  TimeDuration lastExecTime = new TimeDuration(0, 0, 0, 0)
  TimeDuration startFromExecTime = new TimeDuration(0, 0, 0, 0)

  ConfigObject cfg
  MetricClient mc,mcG,mcI
  LinkedHashMap selfMon = [:]

  Closure cleanName = { String str -> str?.split('\\.')?.getAt(0)?.trim()?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase() }


  /**
   * Constructor
   */
  VSphere2Metrics(String cfgFile='config.groovy') {
    cfg = readConfigFile(cfgFile)
    Attributes manifest = getManifestInfo()
    log.info "Initialization: Class: ${this.class.name?.split('\\.')?.getAt(-1)} / Collecting samples: ${cfg?.vcs?.perf_max_samples} = ${cfg?.vcs?.perf_max_samples * 20}sec / Collectors: ${cfg?.vcs?.collectors?.join(',')} / Version: ${manifest?.getValue('Specification-Version')} / Built-Date: ${manifest?.getValue('Built-Date')}"

    if (cfg?.destination?.type?.toLowerCase() == 'graphite') {
      LinkedHashMap parms = [server_host:cfg.graphite.host, server_port:cfg.graphite.port, max_tries:cfg?.destination?.max_tries, prefix:cfg?.graphite?.prefix]
      mc = new MetricClient(parms)
    } else if (cfg?.destination?.type?.toLowerCase() == 'influxdb') {
      LinkedHashMap parms = [server_host:cfg.influxdb.host, server_port:cfg.influxdb.port, max_tries:cfg?.destination?.max_tries, protocol:cfg.influxdb.protocol, server_auth:cfg.influxdb.auth]
      mc = new MetricClient(parms)
    } else if (cfg?.destination?.type?.toLowerCase() == 'both') {
      LinkedHashMap parms_graphite = [server_host:cfg.graphite.host, server_port:cfg.graphite.port, max_tries:cfg?.destination?.max_tries, prefix:cfg?.graphite?.prefix]
      LinkedHashMap parms_influxdb = [server_host:cfg.influxdb.host, server_port:cfg.influxdb.port, max_tries:cfg?.destination?.max_tries, protocol:cfg.influxdb.protocol, server_auth:cfg.influxdb.auth]
      mcG = new MetricClient(parms_graphite)
      mcI = new MetricClient(parms_influxdb)
    } else {
      throw new Exception("Unknown configured destination: ${cfg?.destination?.type}")
    }
  }


  /**
   * Load configuration settings
   *
   * @param cfgFile String with the path of the config file
   * @return ConfigObject with the configuration elements
   */
  ConfigObject readConfigFile(String cfgFile) {
    try {
      ConfigObject cfg = new ConfigSlurper().parse(new File(cfgFile).toURL())
      if (cfg) {
        log.trace "The configuration files: ${cfgFile} was read correctly"
        return cfg
      } else {
        log.error "Verify the content of the configuration file: ${cfgFile}"
        throw new RuntimeException("Verify the content of the configuration file: ${cfgFile}")
      }
    } catch(FileNotFoundException e) {
      log.error "The configuration file: ${cfgFile} was not found"
      throw new RuntimeException("The configuration file: ${cfgFile} was not found")
    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Configuration file exception: ${e?.message}"
      log.debug "Configuration file exception: ${getStackTrace(e)}"
      throw new RuntimeException("Configuration file exception: ${e?.message}")
    }
  }

  /**
   * Retrieves the Manifest Info from the JAR file
   *
   * @return JAR MainAttributes
   */
  Attributes getManifestInfo() {
    Class clazz = this.getClass()
    String className = clazz.getSimpleName() + ".class"
    String classPath = clazz.getResource(className).toString()
    // Class not from JAR
    if (!classPath.startsWith("jar")) { return null }

    String manifestPath = classPath.substring(0, classPath.lastIndexOf('!') + 1) + "/META-INF/MANIFEST.MF"
    Manifest manifest
    try {
      manifest = new Manifest(new URL(manifestPath).openStream())
    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.warn "Manifest: ${e?.message}"
      log.debug "Manifest: ${getStackTrace(e)}"
    }

    return manifest.getMainAttributes()
  }

  // Gets the StackTrace and returns a string
  static String getStackTrace(Throwable t) {
    StringWriter sw = new StringWriter()
    PrintWriter pw = new PrintWriter(sw, true)
    t.printStackTrace(pw)
    pw.flush()
    sw.flush()
    return sw.toString()
  }


  /**
   * Encrypt string
   *
   * @param plaintext String that should be encrypted
   * @return Encrypted String
   */
  private String encrypt(String plaintext) {
    try {
      String salt = java.net.InetAddress.getLocalHost().getHostName()
      String key = 'iFdZMpygE-0'
      Cipher c = Cipher.getInstance('AES')
      byte[] keyBytes = MessageDigest.getInstance('SHA-1').digest("${salt}${key}".getBytes())[0..<16]
      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, 'AES'))
      return c.doFinal(plaintext.bytes).encodeBase64() as String
    } catch(Exception e) {
      return ''
    }
  }
  void encryptPassword(String plaintext) {
      println "${encrypt(plaintext)}"
  }

  /**
   * Decrypt string
   *
   * @param ciphertext Encrypted String that should be decrypted
   * @return Decrypted String
   */
  private String decrypt(String ciphertext) {
    try {
      String salt = java.net.InetAddress.getLocalHost().getHostName()
      String key = 'iFdZMpygE-0'
      Cipher c = Cipher.getInstance('AES')
      byte[] keyBytes = MessageDigest.getInstance('SHA-1').digest("${salt}${key}".getBytes())[0..<16]
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, 'AES'))
      return new String(c.doFinal(ciphertext.decodeBase64()))
    } catch(Exception e) {
      return ''
    }
  }


  /**
   * Connectes to the vSphere server
   *
   * @param vcs URL of the vSphere server
   * @return ServiceInstance
   */
  ServiceInstance vSphereConnect(String vcs) {
    Date ts_start = new Date()
    ServiceInstance si

    try {
      si = new ServiceInstance(new URL(vcs), cfg.vcs.user, decrypt(cfg.vcs.pwd), true)
      si.getServerConnection().getUserSession().setUserAgent("${this.class.name?.split('\\.')?.getAt(-1)}")
      log.info "Connected to vSphere: ${vcs} (${si.getAboutInfo().getApiVersion()}) in ${TimeCategory.minus(new Date(),ts_start)}"
    } catch (InvalidLogin e) {
      log.error "Invalid login vSphere: ${cfg.vcs.user}"
    } catch (RemoteException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Remote exception: ${e?.message}"
      log.debug "Remote exception: ${getStackTrace(e)}"
    } catch (MalformedURLException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "MalformedURLexception: ${e?.message}"
      log.debug "MalformedURLexception: ${getStackTrace(e)}"
    }

    return si
  }

  /**
   * Disconnect from the vSphere server
   *
   * @param si ServiceInstance
   */
  void vSphereDisconnect(ServiceInstance si) {
    Date ts_start = new Date()

    try {
      si.getServerConnection().logout()
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "vSphereDisconnect: ${e?.message}"
      log.debug "vSphereDisconnect: ${getStackTrace(e)}"
    }
  }

  /**
   * PerformanceManager
   *
   * @param si ServiceInstance
   * @return PerformanceManager
   */
  PerformanceManager getPerformanceManager(ServiceInstance si) {
    PerformanceManager perfMgr

    try {
      perfMgr = si?.getPerformanceManager()
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getPerformanceManager: ${e?.message}"
      log.debug "getPerformanceManager: ${getStackTrace(e)}"
    }
    return perfMgr
  }

  /**
   * Get a specific VM
   *
   * @param si ServiceInstance
   * @param name Name of the VM
   * @return InventoryNavigator
   */
  ManagedEntity getVM(ServiceInstance si, String name) {
    ManagedEntity vm
    Folder rootFolder = si.getRootFolder()
    log.info "Getting VM: ${name} from: ${rootFolder.getName()}"

    try {
      vm = new InventoryNavigator(rootFolder).searchManagedEntity("VirtualMachine", name)
      if (vm) {
        log.info "Found ${name} Virtual Machine"
      } else {
        log.error "Did not find ${name} Virtual Machine"
      }

    } catch (RemoteException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getVM: ${e?.message}"
      log.debug "getVM: ${getStackTrace(e)}"
    }

    return vm
  }

  /**
   * Get all the VM's known by the vSphere server
   *
   * @param si ServiceInstance
   * @return InventoryNavigator
   */
  ManagedEntity[] getVMs(ServiceInstance si) {
    ManagedEntity[] vms
    Folder rootFolder = si.getRootFolder()
    log.info "Getting VMs from: ${rootFolder.getName()}"

    try {
      vms = new InventoryNavigator(rootFolder).searchManagedEntities("VirtualMachine")
      if (vms) {
        log.info "Found ${vms.size()} Virtual Machines"
      } else {
        log.warn "Did not find any Virtual Machines"
      }

    } catch (RemoteException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getVMs: ${e?.message}"
      log.debug "getVMs: ${getStackTrace(e)}"
    }

    return vms
  }

  /**
   * Get all the EXSi hosts known by the vSphere server
   *
   * @param si ServiceInstance
   * @return InventoryNavigator
   */
  ManagedEntity[] getHosts(ServiceInstance si) {
    ManagedEntity[] hosts
    Folder rootFolder = si.getRootFolder()
    log.info "Getting ESXi Hosts from: ${rootFolder.getName()}"

    try {
      hosts = new InventoryNavigator(rootFolder).searchManagedEntities("HostSystem")
      if (hosts) {
        log.info "Found ${hosts.size()} Host Systems"
      } else {
        log.error "Did not find any Host Systems"
      }

    } catch (RemoteException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getHosts: ${e?.message}"
      log.debug "getHosts: ${getStackTrace(e)}"
    }

    return hosts
  }

  /**
   * Get Mappings of Hosts and there VMs
   *
   * @param si ServiceInstance
   * @return hm HashMap
  */
  LinkedHashMap getHostMapping(ServiceInstance si) {
    LinkedHashMap hm = [:]

    try {
      ManagedEntity[] ccr = new InventoryNavigator(si.getRootFolder()).searchManagedEntities("ClusterComputeResource")

      List cluster_hosts = []
      ccr.each { ClusterComputeResource cluster ->
        cluster_hosts << cleanName(cluster.getName())
        cluster.getHosts().each { HostSystem host ->
          List host_vms = []
          host.getVms().each { VirtualMachine vm ->
            host_vms << cleanName(vm.getName())
            hm[cleanName(vm.getName())] = ['host_mode':'clustered', 'host_type':'Guest', 'host_cluster':cleanName(cluster.getName()), 'host':cleanName(host.getName())]
          }
          hm[cleanName(host.getName())] = ['host_mode':'clustered', 'host_type':'Host', 'host_cluster':cleanName(cluster.getName()), 'vms':host_vms]
        }

        hm[cleanName(cluster.getName())] = ['host_mode':'clustered', 'host_type':'Cluster', 'host_cluster':cleanName(cluster.getName()), 'hosts':cluster_hosts]
      }

      ManagedEntity[] hosts = new InventoryNavigator(si.getRootFolder()).searchManagedEntities("HostSystem")
      hosts.each { HostSystem host ->
        if(!hm.containsKey(cleanName(host.getName()))) {
          List host_vms = []
          host.getVms().each { VirtualMachine vm ->
            host_vms << cleanName(vm.getName())
            hm[cleanName(vm.getName())] = ['host_mode':'standalone', 'host_type':'Guest', 'host_cluster':null, 'host':cleanName(host.getName())]
          }
          hm[cleanName(host.getName())] = ['host_mode':'standalone', 'host_type':'Host', 'host_cluster':null, 'vms':host_vms]
        }
      }
    } catch (RemoteException e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getMappingVMHost: ${e?.message}"
      log.debug "getMappingVMHost: ${getStackTrace(e)}"
    }

    return hm
  }



  /**
   * Get performace counters and returns a Data strunture containing all there info
   *
   * @param perfMgr A reference to the PerformanceManager used to make the method call.
   * @return LinkedHashMap with all the known performance counters
   */
  LinkedHashMap getPerformanceCounters(PerformanceManager perfMgr) {
    LinkedHashMap perfMetrics = [:]
    PerfCounterInfo[] perfCounters = perfMgr?.getPerfCounter()

    perfCounters.each {
      LinkedHashMap metric = [MetricId:it.getKey(),
                              Metric:"${it.getGroupInfo().getKey()}.${it.getNameInfo().getKey()}_${it.getRollupType()}-${it.getUnitInfo().getKey()}",
                              RollupType:it.getRollupType(),
                              Level:it.getLevel(),
                              PerDeviceLevel:it.getPerDeviceLevel(),
                              StatsType:it.getStatsType(),
                              UnitInfo:it.getUnitInfo().getKey(),
                              NameInfo:it.getNameInfo().getKey(),
                              GroupInfo:it.getGroupInfo().getKey()]

      perfMetrics[it.getKey()] = metric
    }
    return perfMetrics
  }

  /**
   * Create the performance query filter
   *
   * @param me The ManagedObject managed object whose performance statistics are being queried
   * @param metricIds The performance metrics to be retrieved
   * @param maxSample The maximum number of samples to be returned from server
   * @param perfInterval The interval (samplingPeriod) in seconds for which performance statistics are queried
   * @return PerfQuerySpec
   */
  PerfQuerySpec createPerfQuerySpec(ManagedEntity me, PerfMetricId[] metricIds, int maxSample, int perfInterval) {
    PerfQuerySpec qSpec = new PerfQuerySpec()
    qSpec.setEntity(me.getMOR())

    // set the maximum of metrics to be return only appropriate in real-time performance collecting
    if (startFromExecTime.toMilliseconds()) {
      // Retrieve the numbers of samples passed by the parameter 'sf'
      qSpec.setMaxSample(Math.round((startFromExecTime.toMilliseconds()/1000)/20).toInteger())
    } else {
      // Take into account the execution time and get the extra samples.
      int execDelaySamples = Math.round((this.lastExecTime.toMilliseconds()/1000)/20).plus(3)
      qSpec.setMaxSample(maxSample + execDelaySamples)
    }


    qSpec.setMetricId(metricIds)

    //qSpec.setFormat("normal")
    qSpec.setFormat("csv")

    // set the interval to the refresh rate for the entity
    qSpec.setIntervalId(perfInterval)

    return qSpec
  }

  /**
   * Collect the performance metrics
   *
   * @param perfMgr A reference to the PerformanceManager used to make the method call
   * @param maxSample The maximum number of samples to be returned from server
   * @param vm The ManagedObject managed object whose performance statistics are being queried
   * @return PerfEntityMetricBase The metric values for the specified entity or entities.
   */
  //@TimedInterrupt(value=300L, unit=TimeUnit.SECONDS, applyToAllClasses=false, applyToAllMembers=false, checkOnMethodStart=false)
  PerfEntityMetricBase[] getPerfMetrics(PerformanceManager perfMgr,int maxSample,ManagedEntity vm) {
    GParsPool.withPool {
      String vmName = cleanName(vm?.getSummary()?.getConfig()?.getName())
      Long queryTimeout = cfg?.vcs?.perfquery_timeout?.toLong() ?: 60

      PerfProviderSummary pps = perfMgr.queryPerfProviderSummary(vm)
      int refreshRate = pps.getRefreshRate().intValue()
      log.trace "Collecting Performance Metrics RefreshRate: ${refreshRate}"

      PerfMetricId[] pmis = perfMgr.queryAvailablePerfMetric(vm, null, null, refreshRate)
      // For the instance property, specify an asterisk (*) to retrieve instance and aggregate data or a zero-length string ("") to retrieve aggregate data only
      pmis.each { it.setInstance("*") }

      PerfQuerySpec qSpec = createPerfQuerySpec(vm, pmis, maxSample, refreshRate)

      // Use QueryPerf to obtain metrics for multiple entities in a single call.
      // Use QueryPerfComposite to obtain statistics for a single entity with its descendent objects statistics for a host and all its virtual machines, for example.
      // Generate an TimeoutException if the queryTimeout is exceeded
      Future result = { perfMgr.queryPerf(qSpec) }.async().call()
      PerfEntityMetricBase[] pValues = result.get(queryTimeout, TimeUnit.SECONDS)

      return pValues
    }
  }

  /**
   * Generate a Data structure of the collected metrics: DS[MNAME] = [ts:v,ts:v]
   *
   * @param pValues The metric values for the specified entity or entities
   * @param perfMetrics Performance Counters HashMap
   * @param hi Host information HashMap
   * @return LinkedHashMap DS[MNAME] = [ts:v,ts:v]
   */
  LinkedHashMap getValues(pValues,LinkedHashMap perfMetrics,LinkedHashMap hi) {
    LinkedHashMap metricData = [:]

    for (pValue in pValues) {

      if (pValue instanceof PerfEntityMetric) {
        log.debug "Processing PerfEntityMetric: ${pValue.getEntity().getType()} (${pValue.getEntity().get_value()})"

      } else if (pValue instanceof PerfEntityMetricCSV) {
        log.trace "Processing +PerfEntityMetricCSV: ${pValue.getEntity().getType()} (${pValue.getEntity().get_value()})"

        // Get the odd (refreshRate) and even (Time Stamp) elements out of a list
        def (rRate,tStamp) = pValue.getSampleInfoCSV().tokenize(',').collate( 2 ).transpose()

        // Convert incoming time to the Graphite TZ and to the epoch format
        tStamp = tStamp.collect { ((convertTimeZone(it,cfg.vcs?.timezone,cfg?.destination?.timezone)).time.toString().toLong()?.div(1000)).toLong() }

        // Create data structure metricData[Metric][[Timestamp:Value]] for all the instances
        // [net.usage_average-kiloBytesPerSecond:[1339152760000:0, 1339152780000:1, 1339152800000:0, 1339152820000:0, 1339152840000:0, 1339152860000:0]
        pValue.getValue().each {

          String instID = it?.getId()?.getInstance()?.toString()
          String instName

          // Organize the instance name depending on the metrics

          if (!(instID?.trim()) as boolean) {
            instName = 'avg'
          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^datastore.*/) {
            if (hi['datastore'][instID]?.containsKey('type')) {
              instName = "${hi['datastore'][instID]['type']}.${hi['datastore'][instID]['name']}"
            } else {
              log.warn "The datastore CounterID: ${it.getId()?.getCounterId()} Instance: ${instID} has no type"
            }

          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^disk.*/) {
            if (hi['disk'][instID]?.containsKey('type')) {
              instName = "${hi['disk'][instID]['type']}.${hi['disk'][instID]['name']}"
            } else {
              if (!(instID ==~ /^mpx.*/)) {
                log.warn "The disk CounterID: ${it.getId()?.getCounterId()} Instance: ${instID} has no type"
              }
            }

          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^storagePath.*/) {
            if (hi['storagePath'][instID]?.containsKey('pathname')) {
              instName = "${hi['storagePath'][instID]['name']}"

            } else if (hi['storagePath'][instID.split('\\.').getAt(-1)]?.containsKey('pathname')) { // Workaround
              instName = "${hi['storagePath'][instID.split('\\.').getAt(-1)]['name']}"

            } else {
              instName = instID.replaceAll(~/[\s-\._]+/, '_').replaceAll(~/[:]/, '-')
              log.trace "The storagePath CounterID: ${it.getId()?.getCounterId()} Instance: ${instID} has no pathname, using raw path"
            }

          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^sys.*/) {
            if (instID == '/') {
              instName = 'root'
            } else {
              instName = instID.replaceAll(~/\//, '.').replaceAll(~/[_]/, '').trim()
            }

          } else {
            instName = instID
          }

          // Put the metric instance in the middle (metric-type.instance.metric)
          String mpath
          Matcher m
          if ((m = perfMetrics[it.getId().getCounterId()]['Metric'] =~ /(\w+).(.*)/)) {
            mpath = "${m[0][1]}.${instName}.${m[0][2]}".replaceAll(~/[:]/, '-')
          } else {
            log.warn "Could not match metric-type and metric-name, using: ${perfMetrics[it.getId().getCounterId()]['Metric']}}"
            mpath = "${perfMetrics[it.getId().getCounterId()]['Metric']}"
          }

          // Merge back the Time Stamps and Values:
          // def A =  ['One', 'Two', 'Three', 'Four', 'Five']
          // def B =  ['1', '2', '3', '4', '5']
          // [A, B].transpose().inject([:]) { a, b -> a[b[0]] = b[1]; a }
          // Result: [One:1, Two:2, Three:3, Four:4, Five:5]
          metricData[mpath] = [tStamp,it.getValue().split(',')].transpose().inject([:]) { a, b -> a[b[0]] = b[1]; a }
        }

      } else { log.error "UnExpected sub-type of PerfEntityMetricBase: ${pValue.class}" }
    }

    return metricData
  }



  /**
   * Collect the metrics for all the VMs
   *
   * @param perfMgr A reference to the PerformanceManager used to make the method call
   * @param perfMetrics Performance Counters HashMap
   * @param hi Host information HashMap
   * @param maxSample The maximum number of samples to be returned from server
   * @param vms The interval (samplingPeriod) in seconds for which performance statistics are queried
   * @param metricsData Referenca to the shared variable
   */
  void getGuestMetrics(PerformanceManager perfMgr,LinkedHashMap perfMetrics,LinkedHashMap hi,LinkedHashMap hm,int maxSample,ManagedEntity[] vms,LinkedHashMap metricsData) {
    Date ts_start = new Date()

    vms.each { ManagedEntity vm ->
      Date ts_start_vm = new Date()
      PerfEntityMetricBase[] pValues
      String vmName
      String esxHost
      String esxType
      String esxMode
      String esxCluster

      try {
        // Can not collect metrics if VM is not Running
        if (vm?.getSummary()?.getRuntime()?.getPowerState()?.toString() != 'poweredOn') { return }

        vmName = cleanName(vm?.getSummary()?.getConfig()?.getName())
        esxHost = hm[(vmName)]['host']
        esxType = hm[(vmName)]['host_type']
        esxMode = hm[(vmName)]['host_mode']
        esxCluster = hm[(vmName)]['host_cluster']

        pValues = getPerfMetrics(perfMgr,maxSample,vm)
      } catch (TimeoutException e) {
        log.warn "Could not retrieve metrics for the VM: ${vmName} (${esxHost}${esxCluster ? ' - '+ esxCluster : ''}) Timeout exceeded: ${cfg.vcs.perfquery_timeout}:Seconds ${e?.message ?: ''}"

      } catch (Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.warn "Could not retrieve metrics for the VM: ${vmName} (${esxHost}${esxCluster ? ' - '+ esxCluster : ''}) ${e?.message}"
        log.debug "Could not retrieve metrics for the VM: ${vmName} (${esxHost}${esxCluster ? ' - '+ esxCluster : ''}) ${getStackTrace(e)}"
      }

      if (vmName && esxHost && pValues) {
        metricsData[(vmName)] = ['host_type':esxType, 'host':esxHost, 'host_mode':esxMode, 'host_cluster':esxCluster, Metrics:getValues(pValues, perfMetrics, hi)]

        this.selfMon["getGuestMetrics.${vmName}_ms"] = (new Date().time - ts_start_vm.time)
        log.debug "Collected metrics for VM: ${vmName} (${esxHost}${esxCluster ? ' - '+ esxCluster : ''}) in ${TimeCategory.minus(new Date(),ts_start_vm)}"
      } else {
        log.debug "Ignoring metrics from the VM: ${vmName} (${esxHost}${esxCluster ? ' - '+ esxCluster : ''})"
      }
    }

    this.selfMon['getGuestMetrics.total_ms'] = (new Date().time - ts_start.time)
    log.info "Collected Guest metrics in ${TimeCategory.minus(new Date(),ts_start)}"
  }


  /**
   * Collect the metrics for all the Hosts
   *
   * @param perfMgr A reference to the PerformanceManager used to make the method call
   * @param perfMetrics Performance Counters HashMap
   * @param hi Host information HashMap
   * @param maxSample The maximum number of samples to be returned from server
   * @param hosts The interval (samplingPeriod) in seconds for which performance statistics are queried
   * @param metricsData Referenca to the shared variable
   */
  void getHostsMetrics(PerformanceManager perfMgr,LinkedHashMap perfMetrics,LinkedHashMap hi,LinkedHashMap hm,int maxSample,ManagedEntity[] hosts,LinkedHashMap metricsData) {
    Date ts_start = new Date()

    hosts.each { ManagedEntity host ->
      Date ts_start_host = new Date()
      PerfEntityMetricBase[] pValues
      String esxHost
      String esxType
      String esxMode
      String esxCluster

      try {
        // Can not collect metrics if Host is not Running
        if (host?.getSummary()?.getRuntime()?.getPowerState()?.toString() != 'poweredOn') { return }

        esxHost = cleanName(host?.getSummary()?.getConfig()?.getName())
        esxType = hm[(esxHost)]['host_type']
        esxMode = hm[(esxHost)]['host_mode']
        esxCluster = hm[(esxHost)]['host_cluster']

        pValues = getPerfMetrics(perfMgr,maxSample,host)
      } catch (TimeoutException e) {
        log.warn "Could not retrieve metrics for the Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}Timeout exceeded: ${cfg.vcs.perfquery_timeout}:Seconds ${e?.message ?: ''}"

      } catch (Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.warn "Could not retrieve metrics for the Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}${e?.message}"
        log.debug "Could not retrieve metrics for the Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}${getStackTrace(e)}"
      }

      if (esxHost && pValues) {
        metricsData[(esxHost)] = ['host_type':esxType, 'host':esxHost, 'host_mode':esxMode, 'host_cluster':esxCluster, Metrics:getValues(pValues, perfMetrics, hi)]
        this.selfMon["getHostsMetrics.${esxHost}_ms"] = (new Date().time - ts_start_host.time)
        log.debug "Collected metrics for Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}in ${TimeCategory.minus(new Date(),ts_start_host)}"
      } else {
        log.debug "Ignoring metrics for the Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}"
      }
    }
    this.selfMon["getHostsMetrics.total_ms"] = (new Date().time - ts_start.time)
    log.info "Collected Host metrics in ${TimeCategory.minus(new Date(),ts_start)}"
  }

  /**
   * Collects datastore, disk and storagePath information
   *
   * @param hosts The ManagedObject managed object whose performance statistics are being queried
   * @return LinkedHashMap Host information HashMap
   */
  LinkedHashMap getHostInfo(ManagedEntity[] hosts) {
    LinkedHashMap hostInfo = [:]
    LinkedHashMap dsInfo = [:]
    LinkedHashMap diskInfo = [:]
    LinkedHashMap pathInfo = [:]

    hosts.each { ManagedEntity host ->
      try {
        String hostName = cleanName(host?.getSummary()?.getConfig()?.getName())
        // Get datastore info

        HostRuntimeInfo hrti = host?.getRuntime()
        HostSystemConnectionState hscs = hrti?.getConnectionState()
        if (hscs == HostSystemConnectionState.connected) {
          log.debug "getHostInfo: The Host ${hostName} is available (${hscs?.name()})"
        } else {
          log.warn "getHostInfo: The Host ${hostName} is not available (${hscs?.name()})"
          return
        }

        HostStorageSystem hds = host?.getHostStorageSystem() // HostStorageSystem
        HostFileSystemVolumeInfo vi = hds?.getFileSystemVolumeInfo() // HostFileSystemVolumeInfo
        HostFileSystemMountInfo[] mis = vi?.getMountInfo() // HostFileSystemMountInfo
        mis.each {
          HostFileSystemVolume hfsv = it.getVolume() // HostFileSystemVolume
          if (hfsv.metaClass.respondsTo(hfsv, 'getUuid')) {
            dsInfo[hfsv.getUuid()] = [name:hfsv.getName().replaceAll(~/[()]/, '').replaceAll(~/[\s-\.]/, "-"),type:hfsv.getType().trim(), host:hostName]
          } else if (hfsv.type == "vsan") {
            String vsan_id = it.mountInfo.path.split('/')?.getAt(-1).split(':')?.getAt(-1)
            dsInfo[vsan_id] = [name:hfsv.getName().replaceAll(~/[()]/, '').replaceAll(~/[\s-\.]/, "-"),type:hfsv.getType().trim(), host:hostName]
          } else { log.trace "getHostInfo: Type:${hfsv.type} (${hfsv.getClass().getName()}) Path:${it?.mountInfo?.path}" }
        }

        // Get disk info
        HostStorageDeviceInfo hsdi = hds?.getStorageDeviceInfo() // HostStorageDeviceInfo
        ScsiLun[] sls = hsdi?.getScsiLun()
        sls.each { diskInfo[it.getCanonicalName()] = [name:it.getCanonicalName().replaceAll(~/[\s-\._]+/, '_').replaceAll(~/[:]/, '-'), type:it.getLunType().trim(), vendor:it.getVendor().trim().replaceAll(~/[\s-\.:_]+/, '_'), uuid:it.getUuid(), host:hostName] }

        // Get Multipath info
        HostMultipathInfo hmi = hsdi?.getMultipathInfo() // HostMultipathInfo
        hmi?.getLun().each { // HostMultipathInfoLogicalUnit
          HostMultipathInfoPath[] hmips = it.getPath() // HostMultipathInfoPath
          hmips.each { p ->
            pathInfo[p.getName()] = [id:it.getId(), adapter:p.getAdapter(), lun:p.getLun(), name:p.getName().replaceAll(~/[\s-\.]/, '_').replaceAll(~/[:]/, '-')]
          }
        }

        // Link paths with disks
        pathInfo.each { p ->
          diskInfo.each { d ->
            if (p.value['id'] == d.value['uuid']) {
              pathInfo[p.key].pathname = "${p.value['name']}_${d.value['name']}_${d.value['vendor']}"
            }
          }
        }
      } catch(Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.error "getHostInfo: ${e?.message}"
        log.debug "getHostInfo: ${getStackTrace(e)}"
      }
    }

    hostInfo['datastore'] = dsInfo
    hostInfo['disk'] = diskInfo
    hostInfo['storagePath'] = pathInfo
    return hostInfo
  }

  /**
   * Collects datastore, disk and storagePath information
   *
   * @param hosts The ManagedObject managed object whose performance statistics are being queried
   * @return LinkedHashMap Host information HashMap
   */
  LinkedHashMap getGuestInfo(ManagedEntity[] guests) {
    LinkedHashMap guestInfo = [:]
    LinkedHashMap dsInfo = [:]

    guests.each { ManagedEntity guest ->
      try {
        String guest_name = cleanName(guest.getName())

        VirtualDevice[] vmDevs = guest.getPropertyByPath(['config.hardware.device'])
        vmDevs.each { dev ->
          if (dev instanceof VirtualDisk) {
            if( dev.getBacking().backingObjectId ) {
              String ds = dev.getBacking().fileName.replaceFirst(/\[(.*)\].*/, '$1')
              String ds_id = dev.getBacking().backingObjectId
              dsInfo[ds_id] = [name:ds.replaceAll(~/[()]/, '').replaceAll(~/[\s-\.]/, "-"), guest:guest_name]
            }

            if( dev.getBacking().getParent() ) {
              String ds = dev.getBacking().getParent().fileName.replaceFirst(/\[(.*)\].*/, '$1')
              String ds_id = dev.getBacking().getParent().backingObjectId
              dsInfo[ds_id] = [name:ds.replaceAll(~/[()]/, '').replaceAll(~/[\s-\.]/, "-"), guest:guest_name]
            }
          }
        }
      } catch(Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.error "getGuestInfo: ${e?.message}"
        log.debug "getGuestInfo: ${getStackTrace(e)}"
      }
    }

    guestInfo['datastore'] = dsInfo
    return guestInfo
  }

  /**
   * Collects Resource metrics
   *
   * @param si ServiceInstance
   * @param hm Host Mapping HashMap
   * @param metricsData Referenca to the shared variable
   */
  void getResourceMetrics(ServiceInstance si, LinkedHashMap hm, LinkedHashMap metricsData) {
    Date ts_start = new Date()

    try {
      ManagedEntity[] rPools = new InventoryNavigator(si.getRootFolder()).searchManagedEntities("ResourcePool")

      rPools?.each { ResourcePool rPool ->
        Date ts_start_rPool = new Date()
        String node = cleanName(rPool.getOwner().getName())

        if (hm[(node)]?.host_type =~ /Host|Cluster/) {
          LinkedHashMap hostQuickStats = [:]
          Long ts = (new Date().time/1000).toLong()
          String esxType = hm[(node)]['host_type']
          String esxMode = hm[(node)]['host_mode']
          String esxCluster = hm[(node)]['host_cluster']

          ResourcePoolQuickStats rPool_qStats = rPool.getSummary().getQuickStats()
          rPool_qStats.properties?.each {
            if (!(it.value instanceof Integer || it.value instanceof Long)) { return }
            String mpath = "quickstats.${it.key}"
            hostQuickStats[mpath] = [(ts):it.value]
          }

          if (metricsData.containsKey(node)) {
            metricsData[(node)]['Metrics'] << hostQuickStats
          } else {
            metricsData[(node)] = ['host_type':esxType, 'host':node, 'host_mode':esxMode, 'host_cluster':esxCluster, Metrics:hostQuickStats]
          }

          this.selfMon["getResourceMetrics.${node}_ms"] = (new Date().time - ts_start_rPool.time)
          log.debug "Collected ResourcePool metrics for Host: ${node} ${esxCluster ? '('+ esxCluster +') ' : ''}in ${TimeCategory.minus(new Date(),ts_start_rPool)}"
        }
      }

      this.selfMon["getResourceMetrics.total_ms"] = (new Date().time - ts_start.time)
      log.info "Collected ResourcePool metrics in ${TimeCategory.minus(new Date(),ts_start)}"
    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getResourceMetrics: ${e?.message}"
      log.debug "getResourceMetrics: ${getStackTrace(e)}"
    }
  }


  /**
   * Collects VSAN Statistics
   *
   * @param hi Host information HashMap
   * @param hm Host Mapping HashMap
   * @param gi Guest information HashMap
   * @param hosts The ManagedObject managed object whose performance statistics are being queried
   * @param metricsData Referenca to the shared variable
   */
  void getVsanMetrics(LinkedHashMap hi, LinkedHashMap hm, LinkedHashMap gi, ManagedEntity[] hosts,LinkedHashMap metricsData) {
    Date ts_start = new Date()

    hosts.each { ManagedEntity host ->
      if (host?.getSummary()?.getRuntime()?.getPowerState()?.toString() != 'poweredOn') { return }

      String esxHost = ''
      String esxCluster = ''
      try {
        Date ts_start_vsan = new Date()
        LinkedHashMap hostVsanMetrics  = [:]
        esxHost = cleanName(host?.getSummary()?.getConfig()?.getName())
        String esxType = hm[(esxHost)]['host_type']
        String esxMode = hm[(esxHost)]['host_mode']
        esxCluster = hm[(esxHost)]['host_cluster']

        HostVsanInternalSystem vsanInt = host.getHostVsanInternalSystem()
        LazyMap json_vsan_stats
        String jsonTxt_vsan_stats = ''
        try {
          jsonTxt_vsan_stats = vsanInt.queryVsanStatistics(['dom', 'dom-objects', 'lsom', 'disks'] as String[])
          json_vsan_stats = new JsonSlurper().parseText(jsonTxt_vsan_stats)
        } catch(Exception e) {
          log.warn "Collecting VSAN metrics for Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''} - ${e?.message}"
          return
        }

        String jsonTxt_vsan_stats_disks = vsanInt.queryPhysicalVsanDisks()
        LazyMap json_vsan_stats_disks = [:]
        try {
          json_vsan_stats_disks = new JsonSlurper().parseText(jsonTxt_vsan_stats_disks) // Operation not allowed because the VMKernel is shutting down
        } catch(Exception e) {
          json_vsan_stats_disks = [:]
        }

        json_vsan_stats?.get('dom.compmgr.schedStats').each { k, v ->
          Long ts = json_vsan_stats.get('dom.compmgr.schedStats-taken').toLong()
          String mpath = "vsan.compmgr.schedStats.${k}"
          hostVsanMetrics[mpath] = [(ts):v]
        }
        json_vsan_stats?.get('dom.compmgr.stats').each { k, v ->
          Long ts = json_vsan_stats.get('dom.compmgr.stats-taken').toLong()
          String mpath = "vsan.compmgr.stats.${k}"
          hostVsanMetrics[mpath] = [(ts):v]
        }
        json_vsan_stats?.get('dom.client.stats').each { k, v ->
          Long ts = json_vsan_stats.get('dom.client.stats-taken').toLong()
          String mpath = "vsan.client.stats.${k}"
          hostVsanMetrics[mpath] = [(ts):v]
        }
        json_vsan_stats?.get('dom.owner.stats').each { k, v ->
          Long ts = json_vsan_stats.get('dom.owner.stats-taken').toLong()
          String mpath = "vsan.owner.stats.${k}"
          hostVsanMetrics[mpath] = [(ts):v]
        }

        json_vsan_stats?.get('dom.owners.stats').each { String diskID, LazyMap metrics ->
          Long ts = json_vsan_stats.get('dom.owners.stats-taken').toLong()
          HashMap disk = gi['datastore'][diskID]
          if (disk) {
            metrics.each { k,v ->
              String mpath = "vsan.owners.stats.${disk.name}.${disk.guest}.${k}"
              hostVsanMetrics[mpath] = [(ts):v]
            }
          } else {
            //println "No Guest VirtualDisks mapping found for ${diskID}"
          }
        }

        json_vsan_stats?.get('lsom.disks').each { String diskID, LazyMap metrics ->
          Long ts = json_vsan_stats.get('lsom.disks-taken').toLong()

          if (metrics.info.ssd != 'NA') {
            String disk_name = json_vsan_stats_disks instanceof LazyMap ? json_vsan_stats_disks[diskID]?.devName?.getAt(0..-3)?.replaceAll(~/[\s-\._]+/, '_')?.replaceAll(~/[:]/, '-') : diskID
            metrics.each {
              if (it.value instanceof LazyMap) {
                it.value.each { it2 ->
                  if (it2.value instanceof LazyMap) {
                    it2.value.each { it3 ->
                      if (!(it3.value instanceof LazyMap || it3.value instanceof String)) {
                        String mpath = "vsan.lsom.disks.${disk_name}.${it.key}.${it2.key}.${it3.key}"
                        hostVsanMetrics[mpath] = [(ts):it3.value]
                      }
                    }
                  } else {
                    if (!(it2.value instanceof LazyMap || it2.value instanceof String)) {
                      String mpath = "vsan.lsom.disks.${disk_name}.${it.key}.${it2.key}"
                      hostVsanMetrics[mpath] = [(ts):it2.value]
                    }
                  }
                }
              }
            }
          } else if (metrics.info.ssd == 'NA') {
            String disk_name = json_vsan_stats_disks instanceof LazyMap ? json_vsan_stats_disks[diskID]?.devName?.getAt(0..-3)?.replaceAll(~/[\s-\._]+/, '_')?.replaceAll(~/[:]/, '-') : diskID
            metrics.each {
              if (it.value instanceof LazyMap) {
                it.value.each { it2 ->
                  if (it2.value instanceof LazyMap) {
                    it2.value.each { it3 ->
                      if (!(it3.value instanceof LazyMap || it3.value instanceof String)) {
                        String mpath = "vsan.lsom.ssd.${disk_name}.${it.key}.${it2.key}.${it3.key}"
                        hostVsanMetrics[mpath] = [(ts):it3.value]
                      }
                    }
                  } else {
                    if (!(it2.value instanceof LazyMap || it2.value instanceof String)) {
                      String mpath = "vsan.lsom.ssd.${disk_name}.${it.key}.${it2.key}"
                      hostVsanMetrics[mpath] = [(ts):it2.value]
                    }
                  }
                }
              }
            }
          }
        }

        json_vsan_stats?.get('disks.stats').each { String diskID, LazyMap metrics ->
          Long ts = json_vsan_stats.get('disks-taken').toLong()
          String disk_name = diskID.replaceAll(~/[\s-\._]+/, '_').replaceAll(~/[:]/, '-')

          metrics.each {
            if (it.value instanceof LazyMap) {
              it.value.each { it2 ->
                String mpath = "vsan.disks.stats.${disk_name}.${it.key}.${it2.key}"
                hostVsanMetrics[mpath] = [(ts):it2.value]
              }
            } else {
              String mpath = "vsan.disks.stats.${disk_name}.${it.key}"
              hostVsanMetrics[mpath] = [(ts):it.value]
            }
          }
        }

        if(metricsData.containsKey(esxHost)) {
          metricsData[(esxHost)]['Metrics'] << hostVsanMetrics
        } else {
          metricsData[(esxHost)] = ['host_type':esxType, 'host':esxHost, 'host_mode':esxMode, 'host_cluster':esxCluster, Metrics:hostVsanMetrics]
        }
        this.selfMon["getVsanMetrics.${esxHost}_ms"] = (new Date().time - ts_start_vsan.time)
        log.debug "Collected VSAN metrics for Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''}in ${TimeCategory.minus(new Date(),ts_start_vsan)}"

      } catch (Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.error "Collecting VSAN metrics for Host: ${esxHost} ${esxCluster ? '('+ esxCluster +') ' : ''} - ${e?.message}"
        log.debug "getVsanMetrics: ${getStackTrace(e)}"
      }
    }
    this.selfMon["getVsanMetrics.total_ms"] = (new Date().time - ts_start.time)
    log.info "Collected VSAN metrics in ${TimeCategory.minus(new Date(),ts_start)}"
  }

  /**
   * Build Metrics to be consumed by Graphite
   *
   * @param data Metrics Data structure
   * @return ArrayList of Metrics
   */
  ArrayList buildMetrics(LinkedHashMap data) {
    Date ts_start = new Date()
    ArrayList metricList = []
    log.debug "Bulding Metrics"

    try {
      data?.each { node ->
        node?.each { hash ->
          hash.value['Metrics']?.each { metric ->
            metric.value?.each { ts ->
              log.trace "Type:${hash.value['host_type']} / HostCluster:${hash.value['host_cluster']} / HostMode:${hash.value['host_mode']} / Host:${hash.value['host']} / VM:${node.key} / Metric:${metric.key} / Val:${ts.value} / TS:${ts.key}"

              String mpath
              if (hash.value['host_mode'] == 'clustered') {
                if (hash.value['host_type'] == 'Cluster') {
                  mpath = "${hash.value['host_mode']}.${hash.value['host_cluster']}.${hash.value['host_type']}.${metric.key}"
                } else if (hash.value['host_type'] == 'Host') {
                  mpath = "${hash.value['host_mode']}.${hash.value['host_cluster']}.${hash.value['host_type']}.${hash.value['host']}.${metric.key}"
                } else {
                  mpath = "${hash.value['host_mode']}.${hash.value['host_cluster']}.${hash.value['host_type']}.${node.key}.${metric.key}"
                }
              } else {
                if (hash.value['host_type'] == 'Host') {
                  mpath = "${hash.value['host_mode']}.${hash.value['host']}.${hash.value['host_type']}.${metric.key}"
                } else {
                  mpath = "${hash.value['host_mode']}.${hash.value['host']}.${hash.value['host_type']}.${node.key}.${metric.key}"
                }
              }

              Long mtimes = ts.key

              if (metric.key ==~ /(?i)^vsan.*Histogram/){
                ts?.value?.each { h ->
                  BigDecimal mvalue = (h?.value == null || h?.value?.toString()?.isEmpty()) ? 0 : h?.value?.toBigDecimal()
                  metricList << "${mpath}_${h.key} ${mvalue} ${mtimes}\n"
                }
              } else {
                BigDecimal mvalue = (ts?.value == null || ts?.value?.toString()?.isEmpty()) ? 0 : ts?.value?.toBigDecimal()
                if (mvalue) {
                  metricList << "${mpath} ${mvalue} ${mtimes}\n"
                }
              }
            }
          }

          hash.value['Events']?.each { ts ->
            ts.value?.each { event ->
              log.trace "Type:${hash.value['host_type']} / HostCluster:${hash.value['host_cluster']} / HostMode:${hash.value['host_mode']} / Host:${hash.value['host']} / VM:${node.key} / Event:${event.key} / Val:${event.value} / TS:${ts.key}"
              String mpath
              BigDecimal mvalue = (event?.value == null || event?.value?.toString()?.isEmpty()) ? 0 : event?.value?.toBigDecimal()
              if (hash.value['host_mode'] == 'clustered') {
                mpath = "${hash.value['host_mode']}.${hash.value['host_cluster']}.${hash.value['host_type']}.${hash.value['host']}.${event.key}"
              } else {
                mpath = "${hash.value['host_mode']}.${hash.value['host']}.${hash.value['host_type']}.${event.key}"
              }

              metricList << "${mpath} ${mvalue} ${ts.key}\n"
            }
          }
        }
      }
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Building metrics: ${e?.message}"
      log.debug "Building metrics: ${getStackTrace(e)}"
      return metricList
    }
    this.selfMon["buildMetrics.total_ms"] = (new Date().time - ts_start.time)
    log.info "Finished Building ${metricList?.size()} Metrics in ${TimeCategory.minus(new Date(),ts_start)}"

    return metricList
  }


  /**
   * Build Metrics to be consumed by InfluxDB
   *
   * @param data Metrics Data structure
   * @return HashMap of Metrics
   */
  HashMap buildMetricsInfluxDB(LinkedHashMap data) {
    Date ts_start = new Date()
    HashMap metricList = [:]
    Closure strToFloat = { str -> String v = (str?.toFloat() < 0.1) ? str?.toBigDecimal().toPlainString() : str?.toBigDecimal().toPlainString().toBigDecimal() * 1.0; if (v == '0') { 0.0 } else { v } }

    log.debug "Bulding InfluxDB Metrics"

    try {
      data?.each { node ->
        String server = node?.key

        node?.each { hash ->
          ArrayList mData = []

          hash.value['Metrics']?.each { metric ->
            String seriesName
            HashMap mTags = [:]

            try {

              mTags << ['host_type': hash?.value['host_type'], 'host_mode': hash.value['host_mode'], 'server': server ]

              if (hash.value['host_cluster']) {
                mTags << ['host_cluster': hash.value['host_cluster']]
              }

              if (hash?.value['host'] && hash?.value['host'] != server) {
                mTags << ['host': hash?.value['host']]
              }

              switch ( metric.key ) {
                case ~/^(cpu|net|mem|rescpu|power|vflashModule|hbr|storageAdapter|storagePath|virtualDisk)\..*/:
                  Matcher m = Matcher.lastMatcher
                  String mType = m?.group(1)
                  seriesName = "${mType}_${metric.key?.split('\\.')?.getAt(-1)}"
                  String mInstance = metric?.key?.split('\\.')?.getAt(1 .. -2)?.getAt(0) ?: ''

                  if ( mInstance ) {
                    mTags << ['instance': mInstance]
                  }

                break
                case ~/^(datastore|disk)\..*/:
                  Matcher m = Matcher.lastMatcher
                  String mType = m?.group(1)
                  seriesName = "${mType}_${metric.key?.split('\\.')?.getAt(-1)}"
                  String mInstanceType = metric?.key?.split('\\.')?.getAt(1 .. -2)?.getAt(0) ?: ''
                  String mInstance = metric?.key?.split('\\.')?.getAt(2 .. -2)?.getAt(0) ?: ''

                  // Workaround for cases like:
                  //  'disk.avg.read_average-kiloBytesPerSecond'
                  //  'disk.disk.HITACHI-041c.read_average-kiloBytesPerSecond'
                  if (metric.key?.split('\\.')?.getAt(-1) == mInstance) {
                    mInstance = mInstanceType
                    mInstanceType = null
                  }

                  if (mInstanceType) {
                    mTags << ['instance_type': mInstanceType]
                  }
                  if (mInstance) {
                    mTags << ['instance': mInstance.replaceAll(~/\s+/, '-')]
                  }
                case ~/^(quickstats)\..*/:
                  seriesName = "${metric.key.replaceAll(~/[\.]/, '_')}"

                break
                case ~/^(sys|vsan)\..*/:
                  // TODO: Implement
                  return
                break
                default:
                  log.error "Could not match metric: ${metric.key}"
                  return
              }

              log.trace "Server:${server} / SeriesName:${seriesName} / Tags:${mTags} / Points:${metric?.value?.size()}"

              // Build final points structure without null elements
              mData.addAll(
                metric?.value?.collect { ts ->
                  if (!seriesName || !ts?.value) { return }
                  // Ugly Workaround that removes the scientific notation and force the number to be a Float (https://github.com/influxdb/influxdb/issues/3479)
                  String val = strToFloat(ts?.value)
                  "${seriesName},${mTags.sort().collect{ it }.join(',')} value=${val} ${ts?.key?.toLong()}"
                }.findAll()
              )

            } catch(Exception e) {
              StackTraceUtils.deepSanitize(e)
              log.error "Building InfluxDB metric (${seriesName}): ${e?.message}"
              log.debug "Building InfluxDB metric (${seriesName}): ${getStackTrace(e)}"
              return
            }

            metricList[server] = mData
          }
        }
      }
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Building InfluxDB metrics: ${e?.message}"
      log.debug "Building InfluxDB metrics: ${getStackTrace(e)}"
      return metricList
    }

    this.selfMon["buildMetricsInfluxDB.total_ms"] = (new Date().time - ts_start.time)
    log.info "Finished Building InfluxDB Metrics in ${TimeCategory.minus(new Date(),ts_start)}"

    return metricList
  }


  /////////////////////////////////////
  //  Events
  //  https://www.vmware.com/support/developer/vc-sdk/visdk2xpubs/ReferenceGuide/vim.event.Event.html
  ////////////////

  /**
   * Finds vSphere events and associates them to the corresponding ESXi for Graphite
   *
   * @param si ServiceInstance
   * @param maxSample The maximum number of samples to be returned from server
   * @param metricsData Referenca to the shared variable
   */
  void getEvants(ServiceInstance si,LinkedHashMap hm,int maxSample,LinkedHashMap metricsData) {
    try {
      Date ts_start = new Date()
      // Create a filter spec for querying events
      EventFilterSpec efs = new EventFilterSpec()

      // Limit to the following events
      ArrayList HostEvent = ['HostConnectionLostEvent','HostDisconnectedEvent','HostReconnectionFailedEvent','HostShutdownEvent']
      ArrayList ClusterEvent = ['DasAgentUnavailableEvent','DasHostFailedEvent','DrsInvocationFailedEvent','InsufficientFailoverResourcesEvent']
      ArrayList VmEvent = ['VmFailedToPowerOnEvent','VmPoweredOffEvent','VmPoweredOnEvent','VmMigratedEvent','VmFailoverFailed']

      String[] eventFilterList = [HostEvent, ClusterEvent, VmEvent].flatten()
      efs.setType(eventFilterList)

      // Limit to the children of root folder
      EventFilterSpecByEntity eFilter = new EventFilterSpecByEntity()
      eFilter.setEntity(si.getRootFolder().getMOR())
      eFilter.setRecursion(EventFilterSpecRecursionOption.children)

      Date vcDate = si?.currentTime()?.time
      Integer eventTime

      // When using the parameter 'sf'
      if (startFromExecTime.toMilliseconds()) {
        eventTime = (startFromExecTime.toMilliseconds()/1000).toLong()
      } else {
        // Take into account the execution time and get the extra samples.
        int execDelaySamples = Math.round((this.lastExecTime.toMilliseconds()/1000)/20).plus(3)
        eventTime = ((maxSample + execDelaySamples) * 20)
      }

      // Current VC Date minus the eventTime
      use(TimeCategory) {
        vcDate -= eventTime?.second
      }

      EventFilterSpecByTime tFilter = new EventFilterSpecByTime()
      tFilter.setBeginTime(vcDate?.toCalendar())
      efs.setTime(tFilter)

      EventManager em = si.getEventManager()
      Event[] events = em.queryEvents(efs)

      MapWithDefault hostEvents = [:].withDefault { [:].withDefault { [:].withDefault { 0.toBigDecimal() } } }
      HashMap hostType = [:]

      // Sum events generated in the same second
      events?.each { e ->
        Long ts = (e?.getCreatedTime()?.getTime()?.time?.toLong()?.div(1000))?.toLong() ?: 0

        String esxHost = cleanName(e?.getHost()?.getName())
        String esxCluster = hm[(esxHost)]['host_cluster']
        String esxMode = hm[(esxHost)]['host_mode']

        String eventType = e?.getClass()?.getName()?.split('\\.')?.getAt(-1)

        if (esxHost && ts && eventType) {
          hostType[esxHost] = ['host_mode':esxMode, 'host_cluster':esxCluster]
          hostEvents[esxHost][ts][eventType]++
        }
      }
      // Map events to metricsData
      hostEvents?.each { String esxHost, MapWithDefault evts ->
        metricsData[(esxHost)] = ['host_type':'Events', 'host':esxHost, 'host_mode':hostType[esxHost]['host_mode'], 'host_cluster':hostType[esxHost]['host_cluster'], Events:evts]
      }
      this.selfMon["getEvants.total_ms"] = (new Date().time - ts_start.time)
      log.info "Found ${events?.size() ?: 0} Events in ${TimeCategory.minus(new Date(),ts_start)}"

    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getEvants: ${e?.message}"
      log.debug "getEvants: ${getStackTrace(e)}"
    }
  }

  /**
   * Finds vSphere events for InfluxDB
   *
   * @param si ServiceInstance
   * @param maxSample The maximum number of samples to be returned from server
   * @return ArrayList of InfluxDB Metrics
   */
  ArrayList getEvantsInfluxDB(ServiceInstance si,int maxSample) {
    try {
      Date ts_start = new Date()
      String vcHost = si.getServerConnection()?.getUrl()?.getHost()?.split('\\.')?.getAt(0)?.toLowerCase()

      // Create a filter spec for querying events
      EventFilterSpec efs = new EventFilterSpec()

      // Limit to the children of root folder
      EventFilterSpecByEntity eFilter = new EventFilterSpecByEntity()
      eFilter.setEntity(si.getRootFolder().getMOR())
      eFilter.setRecursion(EventFilterSpecRecursionOption.children)

      Date vcDate = si?.currentTime()?.time
      Integer eventTime

      // When using the parameter 'sf'
      if (startFromExecTime.toMilliseconds()) {
        eventTime = (startFromExecTime.toMilliseconds()/1000).toLong()
      } else {
        // Take into account the execution time and get the extra samples.
        int execDelaySamples = Math.round((this.lastExecTime.toMilliseconds()/1000)/20).plus(3)
        eventTime = ((maxSample + execDelaySamples) * 20)
      }

      // Current VC Date minus the eventTime
      use(TimeCategory) {
        vcDate -= eventTime?.second
      }

      EventFilterSpecByTime tFilter = new EventFilterSpecByTime()
      tFilter.setBeginTime(vcDate?.toCalendar())
      efs.setTime(tFilter)

      EventManager em = si.getEventManager()
      Event[] events = em.queryEvents(efs)
      ArrayList mEvents = []

      events.each { e ->
        HashMap mTags = [:]
        // TODO: Add parameterization
        if (e?.getClass()?.getSuperclass()?.getName()?.split('\\.')?.getAt(-1) ==~ /^(Event|AlarmEvent|AuthorizationEvent|CustomFieldEvent|ScheduledTaskEvent|SessionEvent|TaskEvent|TemplateUpgradeEvent|UpgradeEvent).*/) { return }

        Long ts = (e?.getCreatedTime()?.getTime()?.time?.toLong()?.div(1000))?.toLong() ?: 0
        String eventClass = e?.getClass()?.getSuperclass()?.getName()?.split('\\.')?.getAt(-1)
        String eventType = e?.getClass()?.getName()?.split('\\.')?.getAt(-1)
        String eventDc = e?.getDatacenter()?.getName()?.replaceAll(~/([\s,])/, "\\\\\$1")
        String eventCr = e?.getComputeResource()?.getName()?.replaceAll(~/([\s,])/, "\\\\\$1")

        String esxHost = cleanName(e?.getHost()?.getName())
        String esxGuest = cleanName(e?.getVm()?.getName())

        mTags << ['class': eventClass, 'type': eventType, 'vsphere': vcHost]

        if (eventDc) { mTags << ['datacenter': eventDc] }
        if (eventCr) {
          if (e?.getHost()?.getName()?.toLowerCase() == e?.getComputeResource()?.getName()?.toLowerCase()) {
            mTags << ['computeresource': cleanName(eventCr)]
          } else {
            mTags << ['computeresource': eventCr]
          }
        }

        if (esxHost && esxHost != esxGuest) {
          mTags << ['host': esxHost]
        }
        if (esxGuest) { mTags << ['server': esxGuest] }

        mEvents << "events,${mTags.sort().collect{ it }.join(',')} value=1i ${ts ?: ''}"
      }

      this.selfMon["getEvantsInfluxDB.total_ms"] = (new Date().time - ts_start.time)
      log.info "Found ${mEvents?.size() ?: 0}/${events?.size() ?: 0} Events in ${TimeCategory.minus(new Date(),ts_start)}"
      return mEvents

    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getEvantsInfluxDB: ${e?.message}"
      log.debug "getEvantsInfluxDB: ${getStackTrace(e)}"
      return []
    }
  }



  // Converts a time stamp from one Time zone (sourceTZ) another (destTZ)
  Date convertTimeZone(String time, String sourceTZ, String destTZ) {
    final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT)
    Date specifiedTime

    try {
      if (sourceTZ != null) {
        sdf.setTimeZone(TimeZone.getTimeZone(sourceTZ))
      } else {
        sdf.setTimeZone(TimeZone.getDefault()) // default to server's timezone
      }
      specifiedTime = sdf.parse(time)
    } catch (Exception e1) {
      try {
        specifiedTime = new Date().parse(DATE_TIME_FORMAT, time)
      } catch (Exception e2) {
        return time
      }
    }

    // switch timezone
    if (destTZ != null) {
      sdf.setTimeZone(TimeZone.getTimeZone(destTZ))
    } else {
      sdf.setTimeZone(TimeZone.getDefault()) // default to server's timezone
    }

    //sdf.format(specifiedTime)
    new Date().parse("yyyy-MM-dd'T'HH:mm:ss'Z'", sdf.format(specifiedTime))
  }



  /**
   * Dump available counters in vSphere
   *
   */
  void dumpCounters() {
    Date ts_start = new Date()
    log.info "Getting available Counters in vSphere"

    ArrayList vcs = cfg?.vcs?.urls
    vcs.each { vc ->
      ServiceInstance si = vSphereConnect(vc)
      if (!si) { log.error "Error establishing connection to the vSphere server: ${vc}"; return }

      // Find and create performance metrics (counters) hash table
      PerformanceManager perfMgr = getPerformanceManager(si)
      LinkedHashMap perfMetrics = getPerformanceCounters(perfMgr)
      vSphereDisconnect(si)

      println "vSphere: ${vc}"
      perfMetrics.each { c ->
        println "Counter ID: ${c.key}"
        c.value.each {
          println "\t${it}"
        }
      }
    }

    log.info "Finished Collecting vSphere Counters in ${TimeCategory.minus(new Date(),ts_start)}"
  }

  /**
   * Dump metrics
   *
   * 3 Samples + startfrom
   */
  void dumpMetrics(String printType) {
    Date ts_start = new Date()
    log.info "Start Collecting vSphere Metrics"

    ArrayList vcs = cfg?.vcs?.urls
    vcs.each { vc ->
      ServiceInstance si = vSphereConnect(vc)
      if (!si) { log.error "Error establishing connection to the vSphere server: ${vc}"; return }

      // Find and create performance metrics (counters) hash table
      PerformanceManager perfMgr = getPerformanceManager(si)
      LinkedHashMap perfMetrics = getPerformanceCounters(perfMgr)

      ManagedEntity[] hosts = getHosts(si) // Get Hosts
      LinkedHashMap hi = getHostInfo(hosts) // Get Host info
      ManagedEntity[] guests = getVMs(si) // Get VMs
      LinkedHashMap gi = getGuestInfo(guests) // Get Guest info
      LinkedHashMap hm = getHostMapping(si) // Get Host vs Guest Mappings

      // Collect Host and Guest performance metrics
      LinkedHashMap metricsData = [:]
      getHostsMetrics(perfMgr,perfMetrics,hi,hm,cfg.vcs.perf_max_samples,hosts,metricsData)
      getGuestMetrics(perfMgr,perfMetrics,hi,hm,cfg.vcs.perf_max_samples,guests,metricsData)
      getEvants(si,hm,cfg.vcs.perf_max_samples,metricsData)
      getResourceMetrics(si,hm,metricsData)
      getVsanMetrics(hi,hm,gi,hosts,metricsData)

      vSphereDisconnect(si)

      // Print metrics
      println "vSphere: ${vc}"

      switch (printType) {
          case ~/^(?i)Prettyprint/:
              metricsData.each { n ->
                println "${n.key}:"
                n.value.each {
                  if (it.key == 'Metrics') {
                    println "\t${it.key}:"
                    it.value.each {
                      println "\t\t${it.key}: ${it.value}"
                    }
                  } else {
                    println "\t${it.key}: ${it.value}"
                  }
                }
              }
              break
          case ~/^(?i)Graphite/:
              println buildMetrics(metricsData)
              break
          case ~/^(?i)InfluxDB/:
              println buildMetricsInfluxDB(metricsData)?.values()?.collect { it.join('\n') }
              break
          default:
              println "You did not specify the print type: Prettyprint, Graphite or InfluxDB"
              break
      }
    }

    log.info "Finished Collecting vSphere Metrics in ${TimeCategory.minus(new Date(),ts_start)}"
  }




  /**
   * Collect, Process and send the VM Metrics in Parallel
   *
   * @param vcs URL list of the vSphere servers
   */
  void collectMetrics(ArrayList vcs) {
    Date ts_start = new Date()

    GParsPool.withPool(cfg?.vcs?.urls.size()) {
      log.info "Start Collecting vSphere Metrics in parallel using PoolSize: ${cfg?.vcs?.urls.size()}/${PoolUtils.retrieveDefaultPoolSize()} (Current/Max) / Last execution time: ${this.lastExecTime}"

      vcs.eachParallel { vc ->
        String vcHost = cleanName(vc?.replaceAll(~/http.?:\/\/(.*)\/.*/, '$1'))
        Thread.currentThread().name = vcHost

        ServiceInstance si = vSphereConnect(vc)
        if (!si) { log.error "Error establishing connection to the vSphere server: ${vc}"; return }

        try {
          // Find and create performance metrics (counters) hash table
          PerformanceManager perfMgr = getPerformanceManager(si)
          LinkedHashMap perfMetrics = getPerformanceCounters(perfMgr)

          ManagedEntity[] hosts = getHosts(si) // Get Hosts
          ManagedEntity[] guests
          LinkedHashMap hi = getHostInfo(hosts) // Get Host info
          LinkedHashMap hm = getHostMapping(si) // Get Host vs Guest Mappings

          // Collect performance metrics depending on the selection
          LinkedHashMap metricsData = [:]

          if (cfg?.vcs?.collectors?.contains('host')) {
            getHostsMetrics(perfMgr,perfMetrics,hi,hm,cfg.vcs.perf_max_samples,hosts,metricsData)
            getResourceMetrics(si,hm,metricsData)
          }
          if (cfg?.vcs?.collectors?.contains('guest')) {
            if (guests?.size() == null || guests?.size() == 0) { guests = getVMs(si) } // Get VMs
            getGuestMetrics(perfMgr,perfMetrics,hi,hm,cfg.vcs.perf_max_samples,guests,metricsData)
          }
          if (cfg?.vcs?.collectors?.contains('vsan')) {
            if (guests?.size() == null || guests?.size() == 0) { guests = getVMs(si) } // Get VMs
            LinkedHashMap gi = getGuestInfo(guests) // Get Guest info
            getVsanMetrics(hi,hm,gi,hosts,metricsData)
          }
          if (cfg?.vcs?.collectors?.contains('events')) {
            getEvants(si,hm,cfg.vcs.perf_max_samples,metricsData)
          }


          // Send metrics
          if (cfg?.destination?.type?.toLowerCase() == 'graphite') {
            ArrayList metricsDataGraphite = buildMetrics(metricsData)
            this.selfMon['collectMetrics.total_cnt'] = metricsDataGraphite?.size()

            if (cfg?.graphite?.mode?.toLowerCase() == 'pickle') {
              mc.send2GraphitePickle(metricsDataGraphite)
            } else {
              mc.send2Graphite(metricsDataGraphite)
            }

          } else if (cfg?.destination?.type?.toLowerCase() == 'influxdb') {
            ArrayList eventsDataInflux = getEvantsInfluxDB(si,cfg.vcs.perf_max_samples)
            ArrayList metricsDataInflux = buildMetricsInfluxDB(metricsData)?.values()?.collect { it.join('\n') }
            metricsDataInflux.addAll(eventsDataInflux)
            this.selfMon['collectMetrics.total_cnt'] = metricsDataInflux?.size()

            HashMap parms = ['db':cfg?.influxdb.database, 'precision':'s']
            mc.send2InfluxDB(metricsDataInflux, parms)
          } else if (cfg?.destination?.type?.toLowerCase() == 'both') {
            ArrayList metricsDataGraphite = buildMetrics(metricsData)
            this.selfMon['collectMetrics.total_cnt'] = metricsDataGraphite?.size()

            // Graphite
            if (cfg?.graphite?.mode?.toLowerCase() == 'pickle') {
              mcG.send2GraphitePickle(metricsDataGraphite)
            } else {
              mcG.send2Graphite(metricsDataGraphite)
            }

            // InfluxDB
            ArrayList eventsDataInflux = getEvantsInfluxDB(si,cfg.vcs.perf_max_samples)
            ArrayList metricsDataInflux = buildMetricsInfluxDB(metricsData)?.values()?.collect { it.join('\n') }
            metricsDataInflux.addAll(eventsDataInflux)

            HashMap parms = ['db':cfg?.influxdb.database, 'precision':'s']
            mcI.send2InfluxDB(metricsDataInflux, parms)
          }

        } catch(Exception e) {
          StackTraceUtils.deepSanitize(e)
          log.error "GParsPool exception: ${e?.message}"
          log.debug "GParsPool exception: ${getStackTrace(e)}"
        } finally {
          vSphereDisconnect(si)
        }
      }
    }

    this.selfMon['collectMetrics.total_ms'] = (new Date().time - ts_start.time)
    this.lastExecTime = TimeCategory.minus(new Date(),ts_start)
    log.info "Finished Collecting and Sending vSphere Metrics in ${this.lastExecTime}"
  }

  void sendSelfMonMetrics() {
    log.info "Sending SelfMon Metrics"

     // Send metrics
    if (cfg?.destination?.type?.toLowerCase() == 'graphite') {
      if (cfg?.graphite?.mode?.toLowerCase() == 'pickle') {
        mc.send2GraphitePickle(buildSelfMetrics(this.selfMon))
      } else {
        mc.send2Graphite(buildSelfMetrics(this.selfMon))
      }
    } else if (cfg?.destination?.type?.toLowerCase() == 'influxdb') {
      HashMap parms = ['db':cfg?.influxdb.database, 'precision':'s']
      mc.send2InfluxDB(buildSelfMetricsInfluxDB(this.selfMon), parms)

    } else if (cfg?.destination?.type?.toLowerCase() == 'both') {
      HashMap parms = ['db':cfg?.influxdb.database, 'precision':'s']
      mc.send2InfluxDB(buildSelfMetricsInfluxDB(this.selfMon), parms)

      // Graphite
      if (cfg?.graphite?.mode?.toLowerCase() == 'pickle') {
        mc.send2GraphitePickle(buildSelfMetrics(this.selfMon))
      } else {
        mc.send2Graphite(buildSelfMetrics(this.selfMon))
      }
    }
  }

  ArrayList buildSelfMetrics(LinkedHashMap data) {
    ArrayList metricList = []

    try {
      log.debug "Bulding SelfMon Metrics Graphite"

      Long ts = (new Date().time/1000).toLong()
      data.each { String k, Long v ->
        String mpath = "vsphere2metrics.${k.toLowerCase()}"
        metricList << "${mpath} ${v} ${ts}\n"
      }

    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Building SelfMon metrics: ${e?.message}"
      log.debug "Building SelfMon metrics: ${getStackTrace(e)}"
    }

    return metricList
  }

  ArrayList buildSelfMetricsInfluxDB(LinkedHashMap data) {
    ArrayList metricList = []

    try {
      log.debug "Bulding SelfMon Metrics InfluxDB"
      Closure strToFloat = { str -> String v = (str?.toFloat() < 0.1) ? str?.toBigDecimal().toPlainString() : str?.toBigDecimal().toPlainString().toBigDecimal() * 1.0; if (v == '0') { 0.0 } else { v } }

      Long ts = (new Date().time/1000).toLong()
      data.each { String k, Long v ->
        String seriesName = "vsphere2metrics_${k.toLowerCase()?.split('\\.')?.getAt(0)}"
        String instance = k.toLowerCase()?.split('\\.')?.getAt(-1).replaceAll(~/_(ms|cnt)/, '')
        String instance_type = k.toLowerCase()?.split('\\.')?.getAt(-1)?.split('_')?.getAt(1)

        String val = strToFloat(v)
        metricList << "${seriesName},instance=${instance},instance_type=${instance_type} value=${val} ${ts}\n"
      }
    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Building SelfMon metrics: ${e?.message}"
      log.debug "Building SelfMon metrics: ${getStackTrace(e)}"
    }

    return metricList
  }


  /**
   * Run as daemon the Collecting processes
   *
   */
  void runAsDaemon() {
    try {
      while(true) {
        // Collect VM Metrics
        collectMetrics(cfg?.vcs?.urls)
        sendSelfMonMetrics()

        System.gc()

        // Last 1 Minute (3x20s = 60s) / Last 2 Minute (6x20s = 120s) / Last 5 Minute (15x20s = 300s) / Last 10 Minute (30x20s = 600s)
        sleep((cfg?.vcs?.perf_max_samples*20)*1000)
      }
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "runAsDaemon exception: ${e?.message}"
      log.debug "runAsDaemon exception: ${getStackTrace(e)}"
      throw new RuntimeException("runAsDaemon exception: ${e?.message}")
    }
  }


  /**
   * Main execution loop
   *
   */
  static main(args) {
    addShutdownHook { log.info "Shuting down app..." }

    CliBuilder cli = new CliBuilder(usage: '[-dc] [-dm] [-sf <(1..60) Minutes>] [No paramaters Run as Daemon]')
    cli.h(longOpt:'help', 'Usage information')
    cli.dc(longOpt:'dumpcounters', 'Dump available counters, OPTIONAL', required:false)
    cli.dm(longOpt:'dumpmetrics', 'Dump Metrics Prettyprint, Graphite, InfluxDB, OPTIONAL', required:false, type:String, args:1)
    cli.pwd('Encrypt config password', argName:'Password', required:false, type:String, args:1)
    cli.sf(longOpt:'startfrom', 'Start from last samples (Real-Time (1..60)min), OPTIONAL', argName:'Mins', required:false, type:int, args:1)

    OptionAccessor opt = cli.parse(args)
    if (!opt) { return } else if (opt.h | opt.arguments().size() != 0) { cli.usage(); return }

    try {
      VSphere2Metrics main = new VSphere2Metrics()

      // Parse 'Start from' parameter
      if (opt.sf) {
        // Maximum allowed samples is 180 (real-time)
        if ((1..60).contains(opt.sf.toInteger())) {
          main.startFromExecTime = new TimeDuration(0, opt.sf.toInteger(), 0, 0)
        } else {
          println "The start from parameter '${opt.sf}' is Out of range (1..60)"
          return
        }
      }

      if (opt.dc) {
        main.dumpCounters()
      } else if (opt.dm) {
        main.dumpMetrics(opt.dm)
      } else if (opt.pwd) {
        main.encryptPassword(opt.pwd)
      } else {
        main.runAsDaemon()
      }
    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "Main exception: ${e?.message}"
      log.debug "Main exception: ${getStackTrace(e)}"
    }
  }
}


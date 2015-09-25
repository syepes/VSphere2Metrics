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
  MetricClient mc


  /**
   * Constructor
   */
  VSphere2Metrics(String cfgFile='config.groovy') {
    cfg = readConfigFile(cfgFile)
    Attributes manifest = getManifestInfo()
    log.info "Initialization: Class: ${this.class.name?.split('\\.')?.getAt(-1)} / Collecting samples: ${cfg?.vcs?.perf_max_samples} = ${cfg?.vcs?.perf_max_samples * 20}sec / Version: ${manifest?.getValue('Specification-Version')} / Built-Date: ${manifest?.getValue('Built-Date')}"

    if (cfg?.destination?.type?.toLowerCase() == 'graphite') {
      mc = new MetricClient(cfg.graphite.host, cfg.graphite.port, 'tcp', cfg?.graphite?.prefix)
    } else if (cfg?.destination?.type?.toLowerCase() == 'influxdb') {
      mc = new MetricClient(cfg.influxdb.host, cfg.influxdb.port, cfg.influxdb.protocol, null, cfg.influxdb.auth)
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
      StackTraceUtils.deepSanitize(e)
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
      StackTraceUtils.deepSanitize(e)
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
    Date timeStart = new Date()
    ServiceInstance si

    try {
      si = new ServiceInstance(new URL(vcs), cfg.vcs.user, decrypt(cfg.vcs.pwd), true)
      Date timeEnd = new Date()
      log.info "Connected to vSphere (${vcs}) in ${TimeCategory.minus(timeEnd,timeStart)}"
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
    Date timeStart = new Date()

    try {
      si.getServerConnection().logout()
    } catch (Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "vSphereDisconnect: ${e?.message}"
      log.debug "vSphereDisconnect: ${getStackTrace(e)}"
    }
    Date timeEnd = new Date()
    log.info "Disconected from vSphere in ${TimeCategory.minus(timeEnd,timeStart)}"
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
   * Get all the VM's know by the vSphere server
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
   * Get all the EXSi host know by the vSphere server
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
    //qSpec.setEntity(me.getRuntime().getHost())

    // set the maximum of metrics to be return only appropriate in real-time performance collecting
    if (startFromExecTime.toMilliseconds()) {
      // Retrieve the numbers of samples passed by the parameter 'sf'
      qSpec.setMaxSample(Math.round((startFromExecTime.toMilliseconds()/1000)/20).toInteger())
    } else {
      // Take into account the execution time and get the extra samples.
      int execDelaySamples = Math.round((lastExecTime.toMilliseconds()/1000)/20).plus(3)
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
      Date timeStart = new Date()
      String vmName = vm?.getSummary()?.getConfig()?.getName()?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase()
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

      Date timeEnd = new Date()
      log.debug "Collected queryPerf metrics for ${vmName} in ${TimeCategory.minus(timeEnd,timeStart)}"

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
        tStamp = tStamp.collect { ((convertTimeZone(it,cfg.vcs?.timezone,cfg?.destination?.timezone)).time.toString().toLong()/1000).toInteger() }

        // Create data structure metricData[Metric][[Timestamp:Value]] for all the instances
        // [net.usage_average-kiloBytesPerSecond:[1339152760000:0, 1339152780000:1, 1339152800000:0, 1339152820000:0, 1339152840000:0, 1339152860000:0]
        pValue.getValue().each {

          String instID = it?.getId()?.getInstance()?.toString()
          String instName

          // Organize the instance name depending on the metrics
          if (!instID) {
            instName = 'avg'
          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^datastore.*/) {
            if (hi['datastore'][instID]?.containsKey('type')) {
              instName = "${hi['datastore'][instID]['type']}.${hi['datastore'][instID]['name']}"
            } else {
              log.warn "The datastore Instance: ${instID} has no type"
            }

          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^disk.*/) {
            if (hi['disk'][instID]?.containsKey('type')) {
              instName = "${hi['disk'][instID]['type']}.${hi['disk'][instID]['vendor']}-${instID[-4..-1]}"
            } else {
              log.warn "The disk Instance: ${instID} has no type"
            }

          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^storagePath.*/) {
            if (hi['storagePath'][instID]?.containsKey('pathname')) {
              instName = "${hi['storagePath'][instID]['pathname']}"
            } else {
              log.warn "The storagePath Instance: ${instID} has no pathname"
            }
          } else if (perfMetrics[it.getId()?.getCounterId()]['Metric'] ==~ /^sys.*/) {
            if (instID == '/') {
              instName = 'root'
            } else {
              instName = instID.replaceAll(~/\//, '.').replaceAll(~/[_]/, '').trim()
            }
          } else {
            instName = instID ?: 'FIXME'
          }

          // TODO: Try to optimize this
          //def mpath = "${perfMetrics[it.getId().getCounterId()]['Metric']}.${instName}".replaceAll(~/[:]/, '-')
          //mpath = mpath.replaceAll(/(\w+).(.*)/,/$1.$instName.$2/).replaceAll(~/[:]/, '-')

          // Put the metric instance in the middle (metric-type.instance.metric)
          String mpath
          Matcher m
          if ((m = perfMetrics[it.getId().getCounterId()]['Metric'] =~ /(\w+).(.*)/)) {
            mpath = "${m[0][1]}.${instName}.${m[0][2]}".replaceAll(~/[:]/, '-')
          } else {
            mpath = "FIXME.${perfMetrics[it.getId().getCounterId()]['Metric']}"
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
   * @param si ServiceInstance
   * @param perfMgr A reference to the PerformanceManager used to make the method call
   * @param perfMetrics Performance Counters HashMap
   * @param hi Host information HashMap
   * @param maxSample The maximum number of samples to be returned from server
   * @param vms The interval (samplingPeriod) in seconds for which performance statistics are queried
   * @param metricsData Referenca to the shared variable
   */
  void getGuestMetrics(ServiceInstance si,PerformanceManager perfMgr,LinkedHashMap perfMetrics,LinkedHashMap hi,int maxSample,ManagedEntity[] vms,LinkedHashMap metricsData) {

    vms.each { ManagedEntity vm ->
      PerfEntityMetricBase[] pValues
      String vmName,esxHost

      try {
        // Can not collect metrics if VM is not Running
        if (vm?.getSummary()?.getRuntime()?.getPowerState()?.toString() != 'poweredOn') { return }

        vmName = vm?.getSummary()?.getConfig()?.getName()?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase()
        esxHost = new HostSystem(si.getServerConnection(), vm.getRuntime().getHost()).getSummary().getConfig().getName()
        esxHost = esxHost?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase() // Get only the hostname of the FQDN

        pValues = getPerfMetrics(perfMgr,maxSample,vm)
      } catch (TimeoutException e) {
        StackTraceUtils.deepSanitize(e)
        log.error "Could not retrieve metrics for the VM: ${vmName} (${esxHost}) Timeout exceeded: ${cfg.vcs.perfquery_timeout}:Seconds ${e?.message ?: ''}"

      } catch (Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.warn "Could not retrieve metrics for the VM: ${vmName} (${esxHost}) ${e?.message}"
        log.debug "Could not retrieve metrics for the VM: ${vmName} (${esxHost}) ${getStackTrace(e)}"
      }

      if (vmName && esxHost && pValues) {
        metricsData[(vmName)] = [type:'Guest', Host:esxHost, Metrics:getValues(pValues, perfMetrics, hi)]
      } else {
        log.debug "Ignoring metrics from the VM: ${vmName} (${esxHost})"
      }
    }
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
  void getHostsMetrics(PerformanceManager perfMgr,LinkedHashMap perfMetrics,LinkedHashMap hi,int maxSample,ManagedEntity[] hosts,LinkedHashMap metricsData) {

    hosts.each { ManagedEntity host ->
      PerfEntityMetricBase[] pValues
      String esxHost

      try {
        // Can not collect metrics if Host is not Running
        if (host?.getSummary()?.getRuntime()?.getPowerState()?.toString() != 'poweredOn') { return }

        esxHost = host?.getSummary()?.getConfig()?.getName()?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase()

        pValues = getPerfMetrics(perfMgr,maxSample,host)
      } catch (TimeoutException e) {
        StackTraceUtils.deepSanitize(e)
        log.warn "Could not retrieve metrics for the Host: ${esxHost} Timeout exceeded: ${cfg.vcs.perfquery_timeout}:Seconds ${e?.message ?: ''}"

      } catch (Exception e) {
        StackTraceUtils.deepSanitize(e)
        log.warn "Could not retrieve metrics for the Host: ${esxHost} ${e?.message}"
        log.debug "Could not retrieve metrics for the Host: ${esxHost} ${getStackTrace(e)}"
      }


      if (esxHost && pValues) {
        metricsData[(esxHost)] = [type:'Host', Host:esxHost, Metrics:getValues(pValues, perfMetrics, hi)]
      } else {
        log.debug "Ignoring metrics for the Host: ${esxHost}"
      }
    }
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
        String hostName = host?.getSummary()?.getConfig()?.getName()?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase()
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
          } else { log.debug "getHostInfo: Type:${hfsv.type} (${hfsv.getClass().getName()})" }
        }

        // Get disk info
        HostStorageDeviceInfo hsdi = hds?.getStorageDeviceInfo() // HostStorageDeviceInfo
        ScsiLun[] sls = hsdi?.getScsiLun()
        sls.each { diskInfo[it.getCanonicalName()] = [type:it.getLunType().trim(), vendor:it.getVendor().trim(), uuid:it.getUuid(), host:hostName] }

        // Get Multipath info
        HostMultipathInfo hmi = hsdi?.getMultipathInfo() // HostMultipathInfo
        hmi.getLun().each { // HostMultipathInfoLogicalUnit
          HostMultipathInfoPath[] hmips = it.getPath() // HostMultipathInfoPath
          hmips.each { p ->
            pathInfo[p.getName()] = [id:it.getId(), adapter:p.getAdapter(), lun:p.getLun(), name:p.getName()]
          }
        }

        // Link paths with disks
        pathInfo.each { p ->
          diskInfo.each { d ->
            if (p.value['id'] == d.value['uuid']) {
              if (d.value['type']?.toLowerCase() == 'cdrom') {
                pathInfo[p.key].pathname = "${p.value['adapter'].replaceAll('key-vim.host.', '')}-${d.value['type']}-${d.value['vendor']}"
              } else {
                pathInfo[p.key].pathname = "${p.value['adapter'].replaceAll('key-vim.host.', '')}-${d.value['type']}-${d.value['vendor']}-${p.key[-4..-1]}"
              }
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
   * Build Metrics to be consumed by Graphite
   *
   * @param data Metrics Data structure
   * @return ArrayList of Metrics
   */
  ArrayList buildMetrics(LinkedHashMap data) {
    Date timeStart = new Date()
    ArrayList metricList = []
    log.debug "Bulding Metrics"

    try {
      data.each { node ->
        node.each { hash ->
          hash.value['Metrics'].each { metric ->
            metric.value.each { ts ->
              log.trace "Type:${hash.value['type']} / Host:${hash.value['Host']} / VM:${node.key} / Metric:${metric.key} / Val:${ts.value} / TS:${ts.key}"

              String mpath
              if (hash.value['type'] == 'Host') {
                mpath = "${hash.value['Host']}.${hash.value['type']}.${metric.key}"
              } else {
                mpath = "${hash.value['Host']}.${hash.value['type']}.${node.key}.${metric.key}"
              }

              BigDecimal mvalue = (ts.value.toString().isEmpty()) ? 0 : ts.value.toBigDecimal()
              int mtimes = ts.key

              // Only send metrics if they are different than 0
              if (mvalue) {
                metricList << "${mpath} ${mvalue} ${mtimes}\n"
              }
            }
          }
          hash.value['Events'].each { ts ->
            ts.value.each { event ->
              log.trace "Type:${hash.value['type']} / Host:${hash.value['Host']} / VM:${node.key} / Event:${event.key} / Val:${event.value} / TS:${ts.key}"
              String mpath = "${hash.value['Host']}.${hash.value['type']}.${event.key}"
              BigDecimal mvalue = (event?.value?.toString()?.isEmpty()) ? 0 : event?.value?.toBigDecimal()

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
    Date timeEnd = new Date()
    log.info "Finished Building ${metricList?.size()} Metrics in ${TimeCategory.minus(timeEnd,timeStart)}"

    return metricList
  }


  /**
   * Build Metrics to be consumed by InfluxDB
   *
   * @param data Metrics Data structure
   * @return HashMap of Metrics
   */
  HashMap buildMetricsInfluxDB(LinkedHashMap data) {
    Date timeStart = new Date()
    HashMap metricList = [:]
    Closure strToFloat = { str -> String v = (str?.toFloat() < 0.1) ? str?.toBigDecimal().toPlainString() : str?.toBigDecimal().toPlainString().toBigDecimal() * 1.0; if (v == '0') { 0.0 } else { v } }

    log.debug "Bulding InfluxDB Metrics"

    try {
      data.each { node ->
        String server = node?.key

        node.each { hash ->
          ArrayList mData = []

          hash.value['Metrics']?.each { metric ->
            String seriesName
            HashMap mTags = [:]

            try {
              String type = hash?.value['type'] ?: ''
              String host = hash?.value['Host'] ?: ''

              mTags << ['type': type.toString(), 'server': server.toString() ]

              if (host && host != server) {
                mTags << ['host': host.toString()]
              }

              switch ( metric.key ) {
                case ~/^(cpu|net|mem|rescpu|virtualDisk|power|hbr|vflashModule)\..*/:
                  Matcher m = Matcher.lastMatcher
                  String mType = m?.group(1)
                  seriesName = "${mType}_${metric.key?.split('\\.')?.getAt(-1)}"
                  String mInstance = metric?.key?.split('\\.')?.getAt(1 .. -2)?.getAt(0) ?: ''

                  if ( mInstance ) {
                    mTags << ['instance': mInstance.toString()]
                  }

                break
                case ~/^(datastore|disk|storageAdapter|storagePath)\..*/:
                  Matcher m = Matcher.lastMatcher
                  String mType = m?.group(1)
                  seriesName = "${mType}_${metric.key?.split('\\.')?.getAt(-1)}"
                  String mInstanceType = metric?.key?.split('\\.')?.getAt(1 .. -2).getAt(0) ?: ''
                  String mInstance = metric?.key?.split('\\.')?.getAt(2 .. -2).getAt(0) ?: ''

                  if ( mInstanceType ) {
                    mTags << ['instance_type': mInstanceType.toString()]
                  }
                  if ( mInstance ) {
                    mTags << ['instance': mInstance.toString()]
                  }
                break
                case ~/^(sys)\..*/:
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
                  "${seriesName},${mTags.collect{ it }.join(',')} value=${val} ${ts?.key?.toLong()}"
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

    Date timeEnd = new Date()
    log.info "Finished Building InfluxDB Metrics in ${TimeCategory.minus(timeEnd,timeStart)}"

    return metricList
  }


  /////////////////////////////////////
  //  Events
  ////////////////

  /**
   * Finds vSphere events and associates them to the corresponding ESXi
   *
   * @param si ServiceInstance
   * @param maxSample The maximum number of samples to be returned from server
   * @param metricsData Referenca to the shared variable
   */
  void getEvants(ServiceInstance si,int maxSample,LinkedHashMap metricsData) {
    try {
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
      int eventTime

      // When using the parameter 'sf'
      if (startFromExecTime.toMilliseconds()) {
        eventTime = (startFromExecTime.toMilliseconds()/1000).toInteger()
      } else {
        // Take into account the execution time and get the extra samples.
        int execDelaySamples = Math.round((lastExecTime.toMilliseconds()/1000)/20).plus(3)
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
      log.info "Found ${events?.size() ?: 0} events"

      MapWithDefault hostEvents = [:].withDefault { [:].withDefault { [:].withDefault { 0.toBigDecimal() } } }

      // Sum events generated in the same second
      events.each { e ->
        String esxHost = e?.getHost()?.getName()?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase()
        String eventType = e?.getClass()?.getName()?.split('\\.')?.getAt(-1)
        int ts = (e?.getCreatedTime()?.getTime()?.time?.toLong()/1000)?.toInteger() ?: 0

        if (esxHost && ts && eventType) {
          hostEvents[esxHost][ts][eventType]++
        }
      }
      // Map events to metricsData
      hostEvents.each { String esxHost, MapWithDefault evts ->
        metricsData[(esxHost)] = [type:'Events', Host:esxHost, Events:evts]
      }

    } catch(Exception e) {
      StackTraceUtils.deepSanitize(e)
      log.error "getEvants: ${e?.message}"
      log.debug "getEvants: ${getStackTrace(e)}"
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
    Date timeStart = new Date()
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

    Date timeEnd = new Date()
    log.info "Finished Collecting vSphere Counters in ${TimeCategory.minus(timeEnd,timeStart)}"
  }

  /**
   * Dump metrics
   *
   * 3 Samples + startfrom
   */
  void dumpMetrics() {
    Date timeStart = new Date()
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

      // Collect Host and Guest performance metrics
      LinkedHashMap metricsData = [:]
      getHostsMetrics(perfMgr,perfMetrics,hi,cfg.vcs.perf_max_samples,hosts,metricsData)
      getGuestMetrics(si,perfMgr,perfMetrics,hi,cfg.vcs.perf_max_samples,guests,metricsData)
      getEvants(si,cfg.vcs.perf_max_samples,metricsData)

      vSphereDisconnect(si)

      // Print metrics
      println "vSphere: ${vc}"
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
    }

    Date timeEnd = new Date()
    log.info "Finished Collecting vSphere Metrics in ${TimeCategory.minus(timeEnd,timeStart)}"
  }




  /**
   * Collect, Process and send the VM Metrics in Parallel
   *
   * @param vcs URL list of the vSphere servers
   */
  void collectVMMetrics(ArrayList vcs) {
    Date timeStart = new Date()

    GParsPool.withPool(cfg?.vcs?.urls.size()) {
      log.info "Start Collecting vSphere Metrics in parallel using PoolSize: ${cfg?.vcs?.urls.size()}/${PoolUtils.retrieveDefaultPoolSize()} (Current/Max) / Last execution time: ${lastExecTime}"

      vcs.eachParallel { vc ->
        String vcHost = vc?.replaceAll(~/http.?:\/\/(.*)\/.*/, '$1')?.split('\\.')?.getAt(0)?.toLowerCase()
        Thread.currentThread().name = vcHost

        ServiceInstance si = vSphereConnect(vc)
        if (!si) { log.error "Error establishing connection to the vSphere server: ${vc}"; return }

        try {
          // Find and create performance metrics (counters) hash table
          PerformanceManager perfMgr = getPerformanceManager(si)
          LinkedHashMap perfMetrics = getPerformanceCounters(perfMgr)

          ManagedEntity[] hosts = getHosts(si) // Get Hosts
          LinkedHashMap hi = getHostInfo(hosts) // Get Host info
          ManagedEntity[] guests = getVMs(si) // Get VMs

          // Collect Host and Guest performance metrics
          LinkedHashMap metricsData = [:]
          getHostsMetrics(perfMgr,perfMetrics,hi,cfg.vcs.perf_max_samples,hosts,metricsData)
          getGuestMetrics(si,perfMgr,perfMetrics,hi,cfg.vcs.perf_max_samples,guests,metricsData)
          getEvants(si,cfg.vcs.perf_max_samples,metricsData)


          // Send metrics
          if (cfg?.destination?.type?.toLowerCase() == 'graphite') {
            if (cfg?.graphite?.mode?.toLowerCase() == 'pickle') {
              mc.send2GraphitePickle(buildMetrics(metricsData))
            } else {
              mc.send2Graphite(buildMetrics(metricsData))
            }

          } else if (cfg?.destination?.type?.toLowerCase() == 'influxdb') {
            ArrayList metricsDataInflux = buildMetricsInfluxDB(metricsData)?.values()?.collect { it.join('\n') }
            HashMap parms = ['db':cfg?.influxdb.database, 'precision':'s']
            mc.send2InfluxDB(metricsDataInflux, parms)
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

    Date timeEnd = new Date()
    lastExecTime = TimeCategory.minus(timeEnd,timeStart)
    log.info "Finished Collecting and Sending vSphere Metrics in ${lastExecTime}"
  }

  /**
   * Run as daemon the Collecting processes
   *
   */
  void runAsDaemon() {
    try {
      while(true) {
        // Collect VM Metrics
        collectVMMetrics(cfg?.vcs?.urls)

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
    cli.dm(longOpt:'dumpmetrics', 'Dump Metrics, OPTIONAL', required:false)
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
        main.dumpMetrics()
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


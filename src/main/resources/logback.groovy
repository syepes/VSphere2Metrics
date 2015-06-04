import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.core.ConsoleAppender
import ch.qos.logback.core.status.OnConsoleStatusListener
import ch.qos.logback.core.rolling.RollingFileAppender
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy
import static ch.qos.logback.classic.Level.*
import ch.qos.logback.classic.filter.*

import ch.qos.logback.classic.jmx.*
import ch.qos.logback.classic.LoggerContext
import java.lang.management.ManagementFactory


String baseName = 'vSphere2Graphite'
ArrayList classNames = ['com.allthingsmonitoring.vmware.vSphere2Graphite','com.allthingsmonitoring.utils.MetricClient']
Map defaultLevels = setLoggerLevels()

if (System.properties['app.env']?.toUpperCase() == 'DEBUG'){ statusListener(OnConsoleStatusListener) }
scan("30 seconds")
setupAppenders(baseName,defaultLevels)
setupLoggers(classNames)
jmxConfigurator(baseName)


Map setLoggerLevels() {
  Map defaultLevels = [:]
  String env = System.properties['app.env']?.toUpperCase() ?: 'PROD'

  if(env == 'PROD'){ // Only file (info)
    defaultLevels['CONSOLE'] = ERROR
    defaultLevels['FILE'] = INFO
  }else if(env == 'DEV'){ // File (debug) and console (info)
    defaultLevels['CONSOLE'] = INFO
    defaultLevels['FILE'] = DEBUG
  }else if(env == 'DEBUG'){
    defaultLevels['CONSOLE'] = INFO
    defaultLevels['FILE'] = TRACE
  }else{
    defaultLevels['CONSOLE'] = OFF
    defaultLevels['FILE'] = OFF
  }

  return defaultLevels
}


void setupAppenders(String baseName, Map defaultLevels) {
  String HOSTNAME = hostname?.split('\\.')?.getAt(0)?.replaceAll(~/[\s-\.]/, "-")?.toLowerCase() // Get only the hostname of the FQDN

  appender("CONSOLE", ConsoleAppender) {
    // Deny all events with a level below INFO, that is TRACE and DEBUG
    filter(ThresholdFilter) { level = defaultLevels['CONSOLE'] }
    encoder(PatternLayoutEncoder) {
      pattern = "%-35(%d{HH:mm:ss} [%thread]) %highlight(%-5level) %logger - %msg%n%rEx"
    }
  }

  appender("FILE", RollingFileAppender) {
    String pid = System.properties['pid'] ?: '#'
    file = "./logs/${baseName}.log"
    filter(ThresholdFilter) { level = defaultLevels['FILE'] }
    encoder(PatternLayoutEncoder) {
      pattern = "%-35(%d{dd-MM-yyyy - HH:mm:ss.SSS} [${HOSTNAME}] ${pid}:[%thread]) %highlight(%-5level) %logger - %msg%n%rEx"
    }
    rollingPolicy(FixedWindowRollingPolicy) {
      fileNamePattern = "./logs/${baseName}.log.%i"
      minIndex = 1
      maxIndex = 5
    }
    triggeringPolicy(SizeBasedTriggeringPolicy) {
      maxFileSize = "50MB"
    }
  }
}

void setupLoggers(ArrayList classNames) {
  classNames.each { String cn ->
    logger cn, TRACE, ['CONSOLE', 'FILE']
  }
}

void jmxConfigurator(String baseName) {
  jmxConfigurator(baseName)
}


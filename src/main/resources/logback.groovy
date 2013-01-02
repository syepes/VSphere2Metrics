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


def baseName = 'vSphere2Graphite'
def className = 'com.allthingsmonitoring.vSphere2Graphite'
// Get environment variables
def HOSTNAME = hostname.split('\\.')[0].replaceAll(~/[\s-\.]/, "-").toLowerCase() // Get only the hostname of the FQDN
def USER_HOME = System.getProperty("user.home")
//def USER = System.getenv("USER")
def bySecond = timestamp("yyyyMMdd'T'HHmmss")



if (System.properties['app.env']?.toUpperCase() == 'DEBUG'){ statusListener(OnConsoleStatusListener) }
scan("30 seconds")
setupAppenders(baseName,HOSTNAME)
setupLoggers(className)
jmxConfigurator()




def setupAppenders(baseName,HOSTNAME) {
  appender("CONSOLE", ConsoleAppender) {
    // Deny all events with a level below INFO, that is TRACE and DEBUG
    filter(ThresholdFilter) { level = INFO }
    encoder(PatternLayoutEncoder) {
      pattern = "%-35(%d{HH:mm:ss} [%thread]) %highlight(%-5level) %logger - %msg%n%rEx"
    }
  }

  appender("FILE", RollingFileAppender) {
    file = "./logs/${baseName}.log"
    //append = true
    //filter(ThresholdFilter) { level = DEBUG }
    encoder(PatternLayoutEncoder) {
      pattern = "%-35(%d{dd-MM-yyyy - HH:mm:ss.SSS} [${HOSTNAME}] [%thread]) %highlight(%-5level) %logger - %msg%n%rEx"
    }
    rollingPolicy(FixedWindowRollingPolicy) {
      fileNamePattern = "./logs/${baseName}.log.%i"
      minIndex = 1
      maxIndex = 5
    }
    triggeringPolicy(SizeBasedTriggeringPolicy) {
      maxFileSize = "10MB"
    }
  }
}


def setupLoggers(className) {
  def env = System.properties['app.env']?.toUpperCase() ?: 'PROD'

  if(env == 'PROD'){ // Only file (info)
    root INFO, ['FILE']
  }else if(env == 'DEV'){ // File (debug) and console (info)
    logger className, DEBUG, ['FILE']
    root INFO, ['CONSOLE']
  }else if(env == 'DEBUG'){
    logger className, TRACE, ['FILE']
    root INFO, ['CONSOLE']
  }else{
    root OFF, ['CONSOLE', 'FILE']
  }
}

def jmxConfigurator() {
  def contextName = context.name
  def objectNameAsString = MBeanUtil.getObjectNameFor(contextName, JMXConfigurator.class)
  def objectName = MBeanUtil.string2ObjectName(context, this, objectNameAsString)
  def platformMBeanServer = ManagementFactory.getPlatformMBeanServer()
  if (!MBeanUtil.isRegistered(platformMBeanServer, objectName)) {
    JMXConfigurator jmxConfigurator = new JMXConfigurator((LoggerContext) context, platformMBeanServer, objectName)
    try {
      platformMBeanServer.registerMBean(jmxConfigurator, objectName)
    } catch (all) {
      addError("Failed to create mbean", all)
    }
  }
}

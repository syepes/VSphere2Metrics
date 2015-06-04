vcs.urls              = ['https://vcenter-host1/sdk','https://vcenter-host2/sdk']
vcs.user              = 'ReadOnlyUser'
vcs.pwd               = ''              // Generated password
vcs.timezone          = 'GMT-0'
vcs.perfquery_timeout = 60              // Metrics retrieval timeout in Seconds
vcs.perf_max_samples  = 15              // Last 1 Minute (3x20s = 60s)
                                        // Last 2 Minute (6x20s = 120s)
                                        // Last 5 Minute (15x20s = 300s)
                                        // Last 10 Minute (30x20s = 600s)

graphite.host         = 'graphite-host'
graphite.port         = 2004            // standard (2003) / pickle (2004)
graphite.mode         = 'pickle'        // pickle | null
graphite.prefix       = 'ESXi'          // Graphite Metric prefix
graphite.timezone     = 'Europe/Paris'

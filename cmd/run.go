/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
	quicpool "github.com/daeuniverse/quic-go/pool"
	utls "github.com/refraction-networking/utls"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PidFilePath            = "/var/run/dae.pid"
	SignalProgressFilePath = "/var/run/dae.progress"
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
	std           = log.New()
	pprofServer   *http.Server
	metricsServer *http.Server
	commandServer *http.Server
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to std and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				std.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				std.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				internal.AutoSu()
			}

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				std.WithFields(log.Fields{
					"err": err,
				}).Fatalln("Failed to read config")
			}

			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			logger.SetLogger(conf.Global.LogLevel, disableTimestamp, logOpts)

			std.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			Run(conf, []string{filepath.Dir(cfgFile)})
		},
	}
)

func Run(conf *config.Config, externGeoDataDirs []string) {
	control.LogFileDir = filepath.Dir(logFile)

	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)

	startPprofServer(conf.Global.PprofPort)

	// New ControlPlane.
	c, err := newControlPlane(nil, conf, externGeoDataDirs)
	if err != nil {
		std.Fatalln(err)
	}

	// Store config state for subscription updates.
	subscriptionDir := os.Getenv("DAE_LOCATION_SUBSCRIPTION")
	if subscriptionDir == "" {
		subscriptionDir = filepath.Dir(cfgFile)
	}
	c.SetConfigState(cfgFile, subscriptionDir, conf)

	startMetricsServer(conf.Global.MetricsPort)
	startCommandServer(conf.Global.CommandPort, c)

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			<-readyChan
			sdnotify.Ready()
			if !disablePidFile {
				_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
			}
			_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)
		}()
		err := control.GetDaeNetns().With(func() error {
			if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
				return common.Wrap(err, "ListenAndServe")
			}
			return nil
		})
		if err != nil {
			errCh <- err
		} else {
			sigs <- nil
		}
	}()

	defer exit(c)

	reloadingErr := error(nil)
	isSuspend := false
	abortConnections := false
loop:
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case nil:
				if listener == nil {
					// Failed to listen. Exit.
					break loop
				}
				// Serve.
				std.Infoln("[Reload] Serve")
				readyChan := make(chan bool, 1)
				go func() {
					if err := c.Serve(readyChan, listener); err != nil {
						errCh <- common.Wrap(err, "Serve")
					} else {
						sigs <- nil
					}
				}()
				<-readyChan
				sdnotify.Ready()
				if reloadingErr == nil {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
				} else {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+reloadingErr.Error())...), 0644)
				}
				std.Warnln("[Reload] Finished")
			case syscall.SIGUSR2:
				isSuspend = true
				fallthrough
			case syscall.SIGUSR1:
				// Reload signal.
				if isSuspend {
					std.Warnln("[Reload] Received suspend signal; prepare to suspend")
				} else {
					std.Warnln("[Reload] Received reload signal; prepare to reload")
				}
				sdnotify.Reloading()
				_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)
				reloadingErr = nil

				// Load new config.
				abortConnections = os.Remove(AbortFile) == nil
				std.Warnln("[Reload] Load new config")
				var newConf *config.Config
				if isSuspend {
					isSuspend = false
					newConf, err = emptyConfig()
					if err != nil {
						std.WithFields(log.Fields{
							"err": err,
						}).Errorln("[Reload] Failed to reload")
						sdnotify.Ready()
						_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
						continue
					}
					newConf.Global = deepcopy.Copy(conf.Global).(config.Global)
					newConf.Global.WanInterface = nil
					newConf.Global.LanInterface = nil
					newConf.Global.LogLevel = "warning"
				} else {
					var includes []string
					newConf, includes, err = readConfig(cfgFile)
					if err != nil {
						std.Errorf("%+v", common.Wrap(err, "[Reload] Failed to reload"))
						sdnotify.Ready()
						_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
						continue
					}
					std.Infof("Include config files: [%v]", strings.Join(includes, ", "))
				}
				// New logger.
				logger.SetLogger(newConf.Global.LogLevel, disableTimestamp, nil)

				// New control plane.
				obj := c.EjectBpf()
				std.Warnln("[Reload] Load new control plane")
				newC, err := newControlPlane(obj, newConf, externGeoDataDirs)
				if err != nil {
					reloadingErr = err
					std.Errorf("%+v", common.Wrap(err, "[Reload] Failed to reload; try to roll back configuration"))
					// Load last config back.
					newC, err = newControlPlane(obj, conf, externGeoDataDirs)
					if err != nil {
						sdnotify.Stopping()
						obj.Close()
						c.Close()
						std.Errorf("%+v", common.Wrap(err, "[Reload] Failed to roll back configuration"))
					}
					newConf = conf
					std.Errorln("[Reload] Last reload failed; rolled back configuration")
				} else {
					std.Warnln("[Reload] Stopped old control plane")
				}

				// Inject bpf objects into the new control plane life-cycle.
				newC.InjectBpf(obj)

				// Prepare new context.
				oldC := c
				c = newC
				conf = newConf

				// Store config state for subscription updates.
				subscriptionDir := os.Getenv("DAE_LOCATION_SUBSCRIPTION")
				if subscriptionDir == "" {
					subscriptionDir = filepath.Dir(cfgFile)
				}
				c.SetConfigState(cfgFile, subscriptionDir, conf)

				// Ready to close.
				if abortConnections {
					oldC.AbortConnections()
				}
				oldC.Close()
				oldC = nil

				startPprofServer(conf.Global.PprofPort)
				startMetricsServer(conf.Global.MetricsPort)
				startCommandServer(conf.Global.CommandPort, c)

				go runtime.GC()
			case syscall.SIGHUP:
				// Read discriminator to determine update operation.
				code, _, _ := readSignalProgressFile()
				switch code {
				case consts.UpdateDnsSend:
					std.Warnln("[update-dns] Received update-dns signal")
					if !c.UpdatingDns.CompareAndSwap(false, true) {
						std.Warnln("[update-dns] DNS update already in progress; skipping duplicate signal")
						continue
					}
					_ = os.WriteFile(SignalProgressFilePath, []byte{consts.UpdateDnsProcessing}, 0644)
					go func() {
						defer c.UpdatingDns.Store(false)
						if err := c.UpdateDns(); err != nil {
							std.WithFields(log.Fields{
								"err": err,
							}).Errorln("[update-dns] Failed to update dns")
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateDnsError}, []byte("\n"+err.Error())...), 0644)
						} else {
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateDnsDone}, []byte("\nOK")...), 0644)
						}
						go runtime.GC()
					}()
				case consts.UpdateRoutingSend:
					std.Warnln("[update-routing] Received update-routing signal")
					if !c.UpdatingRouting.CompareAndSwap(false, true) {
						std.Warnln("[update-routing] Routing update already in progress; skipping duplicate signal")
						continue
					}
					_ = os.WriteFile(SignalProgressFilePath, []byte{consts.UpdateRoutingProcessing}, 0644)
					go func() {
						defer c.UpdatingRouting.Store(false)
						if err := c.UpdateRouting(); err != nil {
							std.WithFields(log.Fields{
								"err": err,
							}).Errorln("[update-routing] Failed to update routing")
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateRoutingError}, []byte("\n"+err.Error())...), 0644)
						} else {
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateRoutingDone}, []byte("\nOK")...), 0644)
						}
						go runtime.GC()
					}()
				default:
					// Fall through to subscription update (backward compatible,
					// UpdateSubSend or unknown codes all trigger update-sub).
					std.Warnln("[update-sub] Received update-sub signal")
					if !c.UpdatingSub.CompareAndSwap(false, true) {
						std.Warnln("[update-sub] Subscription update already in progress; skipping duplicate signal")
						continue
					}
					_ = os.WriteFile(SignalProgressFilePath, []byte{consts.UpdateSubProcessing}, 0644)
					go func() {
						defer c.UpdatingSub.Store(false)
						if err := c.UpdateSubscriptions(); err != nil {
							std.WithFields(log.Fields{
								"err": err,
							}).Errorln("[update-sub] Failed to update subscriptions")
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateSubError}, []byte("\n"+err.Error())...), 0644)
						} else {
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.UpdateSubDone}, []byte("\nOK")...), 0644)
						}
						go runtime.GC()
					}()
				}
			default:
				std.Infof("Received signal: %v", sig.String())
				break loop
			}
		case err := <-errCh:
			std.Errorf("%+v", err)
			break loop
		}
	}
}

func exit(c *control.ControlPlane) {
	if err := os.Remove(PidFilePath); err != nil {
		std.Errorf("%+v", common.Wrap(err, "failed to remove pid file"))
	}
	if err := control.GetDaeNetns().Close(); err != nil {
		std.Errorf("%+v", common.Wrap(err, "failed to close netns"))
	}
	if e := c.Close(); e != nil {
		std.Errorf("%+v", common.Wrap(e, "failed to close control plane"))
	}
}

func startPprofServer(port uint16) {
	if pprofServer != nil {
		pprofServer.Shutdown(context.Background())
		pprofServer = nil
	}

	if port == 0 {
		return
	}
	pprofServer = &http.Server{Addr: fmt.Sprintf(":%d", port)}
	go pprofServer.ListenAndServe()
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
}

func startMetricsServer(port uint16) {
	// 1. 如果已有服务在运行，先平滑关闭
	if metricsServer != nil {
		// 实际生产中建议给 Shutdown 传一个带 Timeout 的 context
		_ = metricsServer.Shutdown(context.Background())
		metricsServer = nil
	}

	// 2. 如果端口为 0，则不启动
	if port == 0 {
		return
	}

	// 3. 创建极简的 HTTP Server
	// 直接挂载我们自定义的零分配 Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", common.MetricsHandler)

	metricsServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		// 在高性能网络工具中，建议显式设置超时防止连接堆积
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 4. 异步启动
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// 这里可以记录具体的启动错误，比如端口被占用
		}
	}()
}

func startCommandServer(port uint16, handler http.Handler) {
	if commandServer != nil {
		commandServer.Shutdown(context.Background())
		commandServer = nil
	}

	if port == 0 {
		return
	}

	commandServer = &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler}
	go commandServer.ListenAndServe()
}

func newControlPlane(bpf interface{}, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)

	// Free the temp alloc by parsing config.
	runtime.GC()

	/// Init Direct Dialers.
	direct.InitDirectDialers(conf.Global.FallbackResolver, conf.Global.Mptcp, int(conf.Global.SoMarkFromDae))

	// Resolve subscriptions to nodes.
	if !conf.Global.DisableWaitingNetwork {
		epo := 5 * time.Second
		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return direct.Direct.DialContext(ctx, "tcp", addr)
				},
			},
			Timeout: epo,
		}
		log.Infoln("Waiting for network...")
		for i := 0; ; i++ {
			resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
			if err != nil {
				log.Debugf("%+v", common.Wrap(err, "CheckNetwork"))
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					// Do not sleep.
					continue
				}
				time.Sleep(epo)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				break
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			time.Sleep(epo)
		}
		log.Infoln("Network online.")
	}
	if len(conf.Subscription) > 0 {
		log.Infoln("Fetching subscriptions...")
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return direct.Direct.DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: 30 * time.Second,
	}
	subscriptionDir := os.Getenv("DAE_LOCATION_SUBSCRIPTION")
	if subscriptionDir == "" {
		subscriptionDir = filepath.Dir(cfgFile)
	}
	nodeStrs := make([]string, len(conf.Node))
	for i, n := range conf.Node {
		nodeStrs[i] = string(n)
	}
	subStrs := make([]string, len(conf.Subscription))
	for i, s := range conf.Subscription {
		subStrs[i] = string(s)
	}
	tagToNodeList := subscription.ResolveAllSubscriptions(&client, subscriptionDir, nodeStrs, subStrs)

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(subscriptionDir, "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(subscriptionDir, "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if len(conf.Subscription) > 0 {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	c, err = control.NewControlPlane(
		bpf,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		externGeoDataDirs,
	)
	if err != nil {
		return nil, err
	}
	// Call GC to release memory.
	runtime.GC()

	return c, nil
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return common.Errf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func emptyConfig() (conf *config.Config, err error) {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		return nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, err
	}
	return conf, nil
}

func init() {
	utls.SetBufferPool(pool.GetBuffer, pool.PutBuffer)
	utls.NewBytesBufferFunc = func() utls.BytesBuffer { return pool.NewPooledBuffer() }
	quicpool.GetBuffer = pool.GetBuffer
	quicpool.PutBuffer = pool.PutBuffer

	// Inject logrus adapter so quic-go logs (e.g. frame sorter peak stats)
	// flow through dae's logging. Level controlled by QUIC_GO_LOG_LEVEL env var;
	// defaults to silent (matching quic-go's own default).
	quic.SetLogger(common.NewQuicLogger())

	rootCmd.AddCommand(runCmd)
}

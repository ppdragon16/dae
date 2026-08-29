module github.com/daeuniverse/dae

go 1.26.6

require (
	github.com/adrg/xdg v0.5.3
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df
	github.com/cilium/ebpf v0.22.0
	github.com/daeuniverse/outbound v0.0.0-20250722064253-00c4fbb38759
	github.com/daeuniverse/quic-go v0.0.0-20250210145620-2083199a7851
	github.com/fsnotify/fsnotify v1.10.1
	github.com/miekg/dns v1.1.73
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/okzk/sdnotify v0.0.0-20240725214427-1c1fdd37c5ac
	github.com/oschwald/maxminddb-golang/v2 v2.5.0
	github.com/safchain/ethtool v0.7.0
	github.com/sirupsen/logrus v1.10.1
	github.com/spf13/cobra v1.10.2
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/awnumar/fastrand v0.0.0-20210315215012-30ee0990fa2d // indirect
	github.com/awnumar/memcall v0.5.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/onsi/ginkgo/v2 v2.32.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20240715131351-a2f2c23f1771 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.1 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

require (
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-idea v0.0.0-20170306091226-d2fb45a411fb // indirect
	github.com/dgryski/go-rc2 v0.0.0-20150621095337-8a9021637152 // indirect
	github.com/dlclark/regexp2 v1.11.5
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mzz2017/disk-bloom v1.0.1 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/refraction-networking/utls v1.8.2
	github.com/spf13/pflag v1.0.10 // indirect
	gitlab.com/yawning/chacha20.git v0.0.0-20230427033715-7877545b1b37 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

//replace github.com/daeuniverse/outbound => ../outbound_ppdn

replace github.com/daeuniverse/outbound => github.com/ppdragon16/outbound v0.0.0-next.utls.23

//replace github.com/daeuniverse/quic-go => ../quic-go

replace github.com/daeuniverse/quic-go => github.com/ppdragon16/quic-go v0.0.0-next.utls.8

//replace github.com/refraction-networking/utls => ../utls_ppdn

replace github.com/refraction-networking/utls => github.com/ppdragon16/utls v1.8.2-pooled.13

// Vendored fork of cuckoofilter: drop the gob-using ScalableCuckooFilter
// (vmess only uses the basic in-memory Filter), removing the ~512KB
// encoding/gob package-init cost.
replace github.com/seiflotfy/cuckoofilter => ./pkg/cuckoofilter

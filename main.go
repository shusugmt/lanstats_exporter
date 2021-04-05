package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	_ "net/http/pprof"
)

var (
	webConfig      = webflag.AddFlags(kingpin.CommandLine)
	listenAddress  = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9880").String()
	watchInterface = kingpin.Flag("interface", "Interface to watch").Required().String()
	snaplen        = kingpin.Flag("snapshot-length", "Specify pcap snaplen").Default("128").Int32()
	bpfString      = kingpin.Flag("bpf", "Specify BPF for pcap capture").String()
	bufferSize     = kingpin.Flag("buffer-size", "Size of internal buffer").Default("10000").Int()
)

var (
	pcapStatsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "lanstats_pcap_stats",
		Help: "pcap statistics, updated every 1 sec",
	}, []string{"counter"})
	bufferUsageGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "lanstats_buffer_usage",
		Help: "Number of packets stored in internal buffer, updated every 1 sec",
	})
	processedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lanstats_processed",
		Help: "Total packets processed",
	})
	unknownCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lanstats_unknown",
		Help: "Count of Unknown packets",
	})
	unicastCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lanstats_unicast",
		Help: "Count of Unicast ethernet frames",
	})
	etherTypeCounteer = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lanstats_ethernet_type",
		Help: "Count of Broadcast/Multicast ethernet frames, group by EtherType",
	}, []string{"sender", "type"})
	arpRequestSenderCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lanstats_arp_request_sent_by",
		Help: "Count of ARP Requests, group by sender (MAC)",
	}, []string{"sender"})
	arpRequestTargetCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lanstats_arp_request_sent_to",
		Help: "Count of ARP Requests, group by TPA (Target Protocol Address = Target IP Address)",
	}, []string{"target"})
	neighborSolicitSenderCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lanstats_neighbor_solicit_sent_by",
		Help: "Count of ICMPv6 Neighbor Solicit, group by sender (MAC)",
	}, []string{"sender"})
	neighborSolicitTargetCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lanstats_neighbor_solicit_sent_to",
		Help: "Count of ICMPv6 Neighbor Solicit, group by target IPv6 Address",
	}, []string{"target"})
)

func init() {
	prometheus.MustRegister(version.NewCollector("lanstats_exporter"))

	prometheus.MustRegister(pcapStatsGauge)
	prometheus.MustRegister(bufferUsageGauge)

	prometheus.MustRegister(processedCounter)
	prometheus.MustRegister(unknownCounter)
	prometheus.MustRegister(unicastCounter)
	prometheus.MustRegister(etherTypeCounteer)
	prometheus.MustRegister(arpRequestSenderCounter)
	prometheus.MustRegister(arpRequestTargetCounter)
	prometheus.MustRegister(neighborSolicitSenderCounter)
	prometheus.MustRegister(neighborSolicitTargetCounter)
}

func main() {
	os.Exit(run())
}

func capture() {
	handle, err := pcap.OpenLive(*watchInterface, *snaplen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	// Apply BPF if given
	if *bpfString != "" {
		if err := handle.SetBPFFilter(*bpfString); err != nil {
			panic(err)
		}
	}
	// We only care about incoming packets
	handle.SetDirection(pcap.DirectionIn)

	// goroutine for updating pcap stats
	go func() {
		for {
			pcapStats, _ := handle.Stats()
			pcapStatsGauge.WithLabelValues("received").Set(float64(pcapStats.PacketsReceived))
			pcapStatsGauge.WithLabelValues("dropped").Set(float64(pcapStats.PacketsDropped))
			pcapStatsGauge.WithLabelValues("if_dropped").Set(float64(pcapStats.PacketsIfDropped))

			// every 1 sec
			time.Sleep(1 * time.Second)
		}
	}()

	// Create channel to store captured packets
	packetDataCh := make(chan []byte, *bufferSize)

	go func() {
		defer close(packetDataCh)
		for {
			// Read in captured packets and append to channel
			// TODO: handle unrecoverable err
			data, _, _ := handle.ZeroCopyReadPacketData()
			packetDataCh <- data
		}
	}()

	go func() {
		for {
			bufferUsageGauge.Set(float64(len(packetDataCh)))

			// every 1 sec
			time.Sleep(1 * time.Second)
		}
	}()

	// To get best performance, we use custom decoder instead of `PacketSource.Packets()``
	// See:
	// - https://github.com/google/gopacket/issues/457
	// - https://pkg.go.dev/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
	var (
		eth    layers.Ethernet
		arp    layers.ARP
		ipv6   layers.IPv6
		icmpv6 layers.ICMPv6
		ns     layers.ICMPv6NeighborSolicitation
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	parser.SetDecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	parser.AddDecodingLayer(&eth)
	parser.AddDecodingLayer(&arp)
	parser.AddDecodingLayer(&ipv6)
	parser.AddDecodingLayer(&icmpv6)
	parser.AddDecodingLayer(&ns)
	decoded := make([]gopacket.LayerType, 0, 10)

	// main loop: Process packets
	for packetData := range packetDataCh {
		processedCounter.Inc()

		// decode
		parser.DecodeLayers(packetData, &decoded)

		if len(decoded) == 0 {
			// Ethernetですら無いパターン
			// NewDecodingLayerParserのfirstにLayerTypeEthernetを指定しているので
			// 一番最初は必ずEthernetとしてデコードしようとする
			// よってこの条件にマッチするケースは極めてレア
			unknownCounter.Inc()
			continue
		}

		// Ethernetの統計処理
		// Unicast frame(G/L bitがoff)
		if !isGroupAddress(eth.DstMAC) {
			unicastCounter.Inc()
			continue
		} else {
			// Broadcast/Multicast (G/L bitがon)であれば(Src MAC, EtherType)毎にカウントアップする
			etherTypeCounteer.WithLabelValues(eth.SrcMAC.String(), fmt.Sprintf("0x%04x", int(eth.EthernetType))).Inc()
		}

		// decode出来たレイヤー数が1の場合、Ethernetしかデコードされていない
		// これ以降の処理は対象外なのですぐ次のパケットへ
		if len(decoded) == 1 {
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				// We only care about ARP requests
				// 1 = request, 2 = reply
				if arp.Operation == 1 {
					arpRequestSenderCounter.WithLabelValues(eth.SrcMAC.String()).Inc()
					targetIP := net.IPv4(arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
					arpRequestTargetCounter.WithLabelValues(targetIP.String()).Inc()
				}
			case layers.LayerTypeICMPv6NeighborSolicitation:
				neighborSolicitSenderCounter.WithLabelValues(eth.SrcMAC.String()).Inc()
				neighborSolicitTargetCounter.WithLabelValues(ns.TargetAddress.String()).Inc()
			}
		}
	}
}

// G/L bitが1の場合にtrueを返す
func isGroupAddress(hwaddr net.HardwareAddr) bool {
	return (hwaddr[0]&0x01 == 1)
}

func run() int {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("lanstats_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting lanstats_exporter", "version", version.Info())
	level.Info(logger).Log("build_context", version.BuildContext())

	go capture()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := &http.Server{Addr: *listenAddress}
	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
		if err := web.ListenAndServe(srv, *webConfig, logger); err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			level.Info(logger).Log("msg", "Received SIGTERM, exiting gracefully...")
			return 0
		case <-srvc:
			return 1
		}
	}

}

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	sarama "github.com/Shopify/sarama"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"
	proto "github.com/golang/protobuf/proto"
	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
)

//- MaxMind Database ASN
var MMDB *maxminddb.Reader

//- Protocol numbers dict
var protocols = map[uint32]string{
	1:   "ICMP",
	2:   "IGMP",
	4:   "IPv4",
	6:   "TCP",
	17:  "UDP",
	41:  "IPv6",
	47:  "GRE",
	50:  "ESP",
	58:  "IPv6-ICMP",
	89:  "OSPFIGP",
	103: "PIM",
}

//- Allowed interfaces
var lesser = map[string]bool{
	"pe1asrgyes": true,
	"pe1asruios": true,
	"pe1asruiod": true,
}

//SNMP Map --- Put here console output
var interfaces = map[string]string{
	"rointernetgye4:24":  "TenGigE0/0/0/4",
	"rointernetgye4:25":  "TenGigE0/0/0/5",
	"rointernetgye4:170": "TenGigE0/6/0/11",
	"rointernetgye4:232": "Bundle-Ether98",
	"rointernetgye4:188": "Bundle-Ether100",
	"rointernetgye4:216": "Bundle-Ether96",
	"rointernetgye4:211": "Bundle-Ether99",
	"rointernetgye4:183": "Bundle-Ether95",
	"rointernetgye4:228": "Bundle-Ether97",
	"rointernetgye4:22":  "TenGigE0/0/0/2",
	"rointernetgye4:137": "TenGigE0/2/0/11",
	"rointernetgye4:138": "TenGigE0/2/0/12",
	"rointernetgye4:171": "TenGigE0/6/0/12",
	"rointernetgye4:127": "TenGigE0/2/0/1",
	"rointernetgye4:233": "Bundle-Ether93",
	"rointernetgye4:234": "Bundle-Ether200",
	"rointernetgye4:235": "Bundle-Ether250",
	"rointernetgye4:263": "Bundle-Ether252",
	"rointernetgye4:265": "HundredGigE0/4/0/3.500",
	"rointernetgye4:266": "HundredGigE0/4/0/3.510",

	"routercdn2uio:274": "Bundle-Ether80",
	"routercdn2uio:249": "Bundle-Ether112",
	"routercdn2uio:256": "BVI2300",
	"routercdn2uio:243": "BVI2201",
	"routercdn2uio:283": "BVI2301",
	"routercdn2uio:268": "Bundle-Ether114.2100",
	"routercdn2uio:269": "BVI2202",
	"routercdn2uio:265": "Bundle-Ether30",
	"routercdn2uio:267": "Bundle-Ether114",

	"routercdn2gye:306": "Bundle-Ether100",
	"routercdn2gye:294": "BVI2300",
	"routercdn2gye:274": "BVI2201",
	"routercdn2gye:318": "BVI2301",
	"routercdn2gye:312": "Bundle-Ether107.2100",
	"routercdn2gye:307": "Bundle-Ether104",
	"routercdn2gye:126": "TenGigE0/4/0/1",
	"routercdn2gye:276": "Bundle-Ether108",
	"routercdn2gye:305": "Bundle-Ether30",
	"routercdn2gye:311": "Bundle-Ether107",
	"routercdn2gye:443": "BVI2302",
	"routercdn2gye:448": "Bundle-Ether50",

	"rointernetuio1:91":  "Bundle-Ether100",
	"rointernetuio1:109": "Bundle-Ether93",
	"rointernetuio1:92":  "Bundle-Ether200",
	"rointernetuio1:119": "TenGigE0/3/0/1",
	"rointernetuio1:107": "Bundle-Ether90",
	"rointernetuio1:65":  "TenGigE0/7/0/3",
	"rointernetuio1:50":  "TenGigE0/6/0/4",
	"rointernetuio1:122": "Bundle-Ether98",
	"rointernetuio1:161": "TenGigE0/4/0/4",
	"rointernetuio1:174": "Bundle-Ether95",
	"rointernetuio1:36":  "HundredGigE0/0/0/2",

	"roclientesdcgye1:82": "Bundle-Ether99",
	"roclientesdcgye1:46": "TenGigE0/0/0/18",

	"roclientesdcgye2:81": "Bundle-Ether95",
	"roclientesdcgye2:52": "TenGigE0/0/0/12",

	"pe1asrgyes:592": "BVI90",
	"pe1asruios:695": "BVI90",

	"pe2asrgyedc:231": "Bundle-Ether10",

	"pe1asruiod:867": "BVI90",
}

//Exporter
var nodes = map[string]string{
	"10.101.11.211":  "rointernetgye4",
	"201.218.56.129": "routercdn2gye",
	"10.101.21.149":  "rointernetuio1",
	"10.101.21.148":  "routercdn2uio",
	"10.101.11.226":  "pe1asrgyes",
	"10.101.21.208":  "pe1asruios",
	"10.101.107.175": "pe2asrgyedc",
	"10.101.21.219":  "pe1asruiod",
	"10.101.11.223":  "roclientesdcgye1",
	"10.101.11.224":  "roclientesdcgye2",
}

var (
	KafkaTLS   *bool
	KafkaSASL  *bool
	KafkaTopic *string
	KafkaSrv   *string
	KafkaBrk   *string

	KafkaLogErrors *bool

	KafkaHashing *bool
	KafkaKeying  *string
	KafkaVersion *string

	kafkaConfigVersion sarama.KafkaVersion = sarama.V0_11_0_0
)

type KafkaState struct {
	FixedLengthProto bool
	producer         sarama.AsyncProducer
	topic            string
	hashing          bool
	keying           []string
}

// SetKafkaVersion sets the KafkaVersion that is used to set the log message format version
func SetKafkaVersion(version sarama.KafkaVersion) {
	kafkaConfigVersion = version
}

// ParseKafkaVersion is a pass through to sarama.ParseKafkaVersion to get a KafkaVersion struct by a string version that can be passed into SetKafkaVersion
// This function is here so that calling code need not import sarama to set KafkaVersion
func ParseKafkaVersion(versionString string) (sarama.KafkaVersion, error) {
	return sarama.ParseKafkaVersion(versionString)
}

func RegisterFlags() {
	KafkaTLS = flag.Bool("kafka.tls", false, "Use TLS to connect to Kafka")
	KafkaSASL = flag.Bool("kafka.sasl", false, "Use SASL/PLAIN data to connect to Kafka (TLS is recommended and the environment variables KAFKA_SASL_USER and KAFKA_SASL_PASS need to be set)")
	KafkaTopic = flag.String("kafka.topic", "flow-messages", "Kafka topic to produce to")
	KafkaSrv = flag.String("kafka.srv", "", "SRV record containing a list of Kafka brokers (or use kafka.out.brokers)")
	KafkaBrk = flag.String("kafka.brokers", "127.0.0.1:9092,[::1]:9092", "Kafka brokers list separated by commas")

	KafkaLogErrors = flag.Bool("kafka.log.err", false, "Log Kafka errors")

	KafkaHashing = flag.Bool("kafka.hashing", false, "Enable partitioning by hash instead of random")
	KafkaKeying = flag.String("kafka.key", "SamplerAddress,DstAS", "Kafka list of fields to do hashing on (partition) separated by commas")
	KafkaVersion = flag.String("kafka.version", "0.11.0.0", "Log message version (must be a version that parses per sarama.ParseKafkaVersion)")
}

func StartKafkaProducerFromArgs(log utils.Logger) (*KafkaState, error) {
	kVersion, err := ParseKafkaVersion(*KafkaVersion)
	if err != nil {
		return nil, err
	}
	SetKafkaVersion(kVersion)
	addrs := make([]string, 0)
	if *KafkaSrv != "" {
		addrs, _ = utils.GetServiceAddresses(*KafkaSrv)
	} else {
		addrs = strings.Split(*KafkaBrk, ",")
	}
	return StartKafkaProducer(addrs, *KafkaTopic, *KafkaHashing, *KafkaKeying, *KafkaTLS, *KafkaSASL, *KafkaLogErrors, log)
}

func StartKafkaProducer(addrs []string, topic string, hashing bool, keying string, useTls bool, useSasl bool, logErrors bool, log utils.Logger) (*KafkaState, error) {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = kafkaConfigVersion
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = logErrors
	if useTls {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error initializing TLS: %v", err))
		}
		kafkaConfig.Net.TLS.Enable = true
		kafkaConfig.Net.TLS.Config = &tls.Config{RootCAs: rootCAs}
	}

	var keyingSplit []string
	if hashing {
		kafkaConfig.Producer.Partitioner = sarama.NewHashPartitioner
		keyingSplit = strings.Split(keying, ",")
	}

	if useSasl {
		if !useTls && log != nil {
			log.Warn("Using SASL without TLS will transmit the authentication in plaintext!")
		}
		kafkaConfig.Net.SASL.Enable = true
		kafkaConfig.Net.SASL.User = os.Getenv("KAFKA_SASL_USER")
		kafkaConfig.Net.SASL.Password = os.Getenv("KAFKA_SASL_PASS")
		if kafkaConfig.Net.SASL.User == "" && kafkaConfig.Net.SASL.Password == "" {
			return nil, errors.New("Kafka SASL config from environment was unsuccessful. KAFKA_SASL_USER and KAFKA_SASL_PASS need to be set.")
		} else if log != nil {
			log.Infof("Authenticating as user '%s'...", kafkaConfig.Net.SASL.User)
		}
	}

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		return nil, err
	}
	state := KafkaState{
		producer: kafkaProducer,
		topic:    topic,
		hashing:  hashing,
		keying:   keyingSplit,
	}

	if logErrors {
		go func() {
			for {
				select {
				case msg := <-kafkaProducer.Errors():
					if log != nil {
						log.Error(msg)
					}
				}
			}
		}()
	}

	return &state, nil
}

func HashProto(fields []string, flowMessage *flowmessage.FlowMessage) string {
	var keyStr string

	if flowMessage != nil {
		vfm := reflect.ValueOf(flowMessage)
		vfm = reflect.Indirect(vfm)

		for _, kf := range fields {
			fieldValue := vfm.FieldByName(kf)
			if fieldValue.IsValid() {
				keyStr += fmt.Sprintf("%v-", fieldValue)
			}
		}
	}

	return keyStr
}

func (s KafkaState) SendKafkaFlowMessage(flowMessage *flowmessage.FlowMessage) {
	var key sarama.Encoder
	if s.hashing {
		keyStr := HashProto(s.keying, flowMessage)
		key = sarama.StringEncoder(keyStr)
	}

	// === Mutations al paquete netflow
	//var err error
	flowMessage = parseFlow(flowMessage)
	//if err != nil {
	//	return //- Err means blocked interface netflow
	//}
	//b2, _ := json.Marshal(flowMessage)
	//fmt.Println(string(b2))
	// === Editado por Gustavo Santiago - 2020-10-05

	//if flowMessage != nil {
	var b []byte
	if !s.FixedLengthProto {
		b, _ = proto.Marshal(flowMessage)
	} else {
		buf := proto.NewBuffer([]byte{})
		buf.EncodeMessage(flowMessage)
		b = buf.Bytes()
	}
	s.producer.Input() <- &sarama.ProducerMessage{
		Topic: s.topic,
		Key:   key,
		Value: sarama.ByteEncoder(b),
	}
	//}
}

func parseFlow(f *flowmessage.FlowMessage) *flowmessage.FlowMessage {
	//- Fixed Sampling Rate at 1000
	f.SamplingRate = 1000

	//- Exporter mapping
	node := nodes[net.IP(f.SamplerAddress).String()]
	if node == "" {
		node = net.IP(f.SamplerAddress).String()
	}
	f.Exporter = node

	//- Port mapping
	ingressPort := interfaces[node+":"+strconv.Itoa(int(f.InIf))]
	if ingressPort == "" {
		//if lesser[node] { // - Si es un nodo turro - ignora
		//	return nil
		//}
		ingressPort = strconv.Itoa(int(f.InIf))
	}
	f.IngressPort = ingressPort

	//- Gate mapping
	f.Gate = f.Exporter + ":" + f.IngressPort

	// Explicit excluded
	//if f.Gate == "routercdn2gye:Bundle-Ether30" {
	//	return f, errors.New(fmt.Sprintf("Excluded interface %s", f.Gate))
	//}
	//if f.Exporter == "pe1asrgyes" || f.Exporter == "pe1asruios" || f.Exporter == "pe1asruiod" {
	//	if !allowed[f.Gate] {
	//		return f, errors.New(fmt.Sprintf("Excluded interface %s", f.Gate))
	//	}
	//}

	//- Protocol number
	protocol := protocols[f.Proto]
	if protocol == "" {
		protocol = strconv.Itoa(int(f.Proto))
	}
	f.Protocol = protocol

	//- ASN & OrgName (Src&Dst) -- se invierte la direccion por ser ingress
	f.SrcAS, f.SrcASOrg = lookupASN(net.IP(f.DstAddr).String())
	f.DstAS, f.DstASOrg = lookupASN(net.IP(f.SrcAddr).String())
	if f.SrcAS == 0 {
		f.SrcASOrg = "private"
	}
	if f.DstAS == 0 {
		f.DstASOrg = "private"
	}

	//- Invert Addresses & Ports
	f.ClientAddr = net.IP(f.DstAddr).String()
	f.ServerAddr = net.IP(f.SrcAddr).String()
	tmp := f.SrcPort
	f.SrcPort = f.DstPort
	f.DstPort = tmp

	return f
}

// This example shows how to decode to a struct
func lookupASN(ip string) (uint32, string) {
	ip2 := net.ParseIP(ip)
	var record struct {
		ASN uint32 `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}
	err := MMDB.Lookup(ip2, &record)
	if err != nil {
		log.Fatal(err)
	}
	return record.ASN, record.Org
}

func (s KafkaState) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		s.SendKafkaFlowMessage(msg)
	}
}

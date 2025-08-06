package main

import (
	"fmt"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"regexp"
	"strings"
	"log"
	"os"
	"syscall"
	"github.com/pborman/getopt/v2"
	"gopkg.in/yaml.v2"
	"gopkg.in/ldap.v2"
)

type Connection struct {
	Host string
	Port int
	TLS bool
	StartTLS bool
	Tls_verify_cert bool
	CA_cert_path string
}


type Config struct {
	Connections []Connection
	Search struct {
		Public_key_attr string
		Uid_attr string
		Search_Base string
		Search_filter string
		Bind_DN string
		Bind_Passwd string
	}
}

type StatInfo struct {
	Uid uint32
	Gid uint32
	Mode os.FileMode
}

var logger *log.Logger
var quiet *bool

func get_ca_certs(path string) []byte {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Fatalf(": Could not open CA certs file. [%s]", path)
	}
	return buf
}

// must be fixed.
func get_tls_config(conf Connection) *tls.Config{
	ca_certs := get_ca_certs(conf.CA_cert_path)
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(ca_certs)

	if !ok {
		logger.Fatalln(": Could not append CA certs file.")		
	}

	var tlsConfig *tls.Config
	if conf.Tls_verify_cert {
		tlsConfig = &tls.Config{ RootCAs: roots, ServerName: conf.Host}
	} else {
		tlsConfig = &tls.Config{ RootCAs: roots, InsecureSkipVerify: true}
	}
	return tlsConfig
}

func get_search_request(uid string, conf Config) *ldap.SearchRequest {
	base := conf.Search.Search_Base
	uid_attr := conf.Search.Uid_attr
	attrs := conf.Search.Public_key_attr
	_tmp_filter := strings.TrimSpace(conf.Search.Search_filter)
	
	if uid_attr == "" || base == "" || attrs == "" {
		logger.Fatal("search_base,uid_addr or public_key_attr must be specified")
	}

	var search_filter string
	if _tmp_filter == "" {
		search_filter = fmt.Sprintf("(%s=%s)", uid_attr, uid)
	} else {
		r := regexp.MustCompile("^\\(.*\\)$")
		if r.MatchString(_tmp_filter) {
			search_filter = fmt.Sprintf("(&(%s=%s)%s)",uid_attr, uid, _tmp_filter)
		} else {
			search_filter = fmt.Sprintf("(&(%s=%s)(%s))",uid_attr, uid, _tmp_filter)
		}
	}

	ret := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, //size limit
		0, //time limit
		false, // types only
		search_filter,
		[]string{attrs},
		nil,
	)
	return ret
}

func get_stat_info(info *StatInfo, path string) {
	finfo, err := os.Stat(path)
	if err != nil {
		logger.Fatal("Could not get the File's Information. [%v]", err)
	}
	info.Uid = finfo.Sys().(*syscall.Stat_t).Uid
	info.Gid = finfo.Sys().(*syscall.Stat_t).Gid
	info.Mode = finfo.Mode()
}

func compare_owner(bin, conf *StatInfo) bool {
	var ret bool
	if bin.Uid == conf.Uid {
		ret = true
	} else {
		ret = false
	}
	return ret
}

func check_input_value(args []string) bool {
	if len(args) != 1 {
		logger.Fatal(": only one argument is permitted.")
	}
	_uid := args[0]
	r := regexp.MustCompile("\\*")
	if r.MatchString(_uid) {
		logger.Fatal(": '*' MUST not be included in the argument.")
	}
	return true
}

func check_conf_permission(info *StatInfo) bool {
	var _oe, _ow, _or uint32
	_oe = 1 << 2
	_ow = 1 << 1
	_or = 1
	perm := uint32(info.Mode.Perm())
	// check other exec bit
	if _oe&perm != 0 || _ow&perm != 0 || _or&perm != 0 {
		logger.Fatal(": Any 'other' permissions MUST be dropped.")
	}
	return false
}	

func check_config_file(bin, conf string) bool {
	var iBin,iConf StatInfo
	//	get_stat_info(&iBin, bin)
	iBin.Uid = uint32(os.Geteuid())
	iBin.Gid = uint32(os.Getegid())
	get_stat_info(&iConf, conf)
	check_conf_permission(&iConf)
	if !compare_owner(&iBin, &iConf) {
		logger.Fatal("Config file must be owned by the executor.")
	}
	return false
}

func main() {
	var conf_file = "/root/bin/fetchSshKey.yml"
	logger = log.New(os.Stderr, "fetchSshKey: ",log.LstdFlags)
	// set option parser
	helpFlag := getopt.BoolLong("help", 'h', "Display this help.")	
	getopt.FlagLong(&conf_file, "config", 'c', "Specify the config file path.")
	quiet := getopt.BoolLong( "quiet", 'q', "Suppress logging.")
	getopt.Parse()
	args := getopt.Args()

	if *quiet {
		logger.SetOutput(ioutil.Discard)
	} 
	
	if *helpFlag {
		getopt.Usage()
		os.Exit(0)
	}

	check_input_value(args)
	check_config_file(os.Args[0], conf_file)
	buf, err := ioutil.ReadFile(conf_file)
	
	if err != nil {
		logger.Fatalf("Could not read the confgiuration file. [%s]", conf_file)
	}
	
	var d Config
	err = yaml.Unmarshal(buf, &d)

	if err != nil {
		logger.Fatalf("YAML [%s]: parse error [%v]", conf_file, err)
	}
	
	r := regexp.MustCompile("(?i:.*password.*)|(?i:.*passwd.*)")
	if r.MatchString(d.Search.Public_key_attr) {
		logger.Fatal("Any attibute-value pairs related to 'password' cannot be retrieved.") 
	}
	
	var l *ldap.Conn
	_confs := d.Connections
	for i := 0; i < len(_confs); i++ {
		if _confs[i].TLS {
			tlsConfig := get_tls_config(_confs[i])
			l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", _confs[i].Host, _confs[i].Port), tlsConfig)
			if l != nil {
				break
			} else {
				logger.Printf(":Could not connect to the host. [%s]", _confs[i].Host)
			}
		} else {
			l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", _confs[i].Host, _confs[i].Port))
			if l != nil {
				if _confs[i].StartTLS {
					tlsConfig := get_tls_config(_confs[i])
					err = l.StartTLS(tlsConfig)
					if err != nil {
						logger.Printf(":Could not establish a secure connection [%v]", err)
					}
				}
				break
			} else {
				logger.Printf(":Could not connect to the host. [%s]", _confs[i].Host)
			}
		}
	}

	if l == nil {
		logger.Fatalf(":Could not connect to all the servers [%v]", err)
	}
	defer l.Close()
	
	_uid := args[0]
	searchRequest := get_search_request(_uid, d)
	if d.Search.Bind_DN != "" && d.Search.Bind_Passwd != "" {
		err = l.Bind(d.Search.Bind_DN, d.Search.Bind_Passwd)
		if err != nil {
			logger.Fatalf(":Could not bind with this DN w/ Password. [%s w/ *****]", d.Search.Bind_DN)
		}
	}
	
	sr, err := l.Search(searchRequest)

	if err != nil {
		logger.Fatalf(":Some error occured during LDAP search operation. [%v]", err)
	}

	for _, entry := range sr.Entries {
		for _, attr := range entry.GetAttributeValues(d.Search.Public_key_attr) {
			fmt.Printf("%s\n",attr)
		}
	}
}

package lib

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/state"
)

// Cert
// https://groups.google.com/d/msg/mailing.openssl.users/gMRbePiuwV0/wTASgPhuPzkJ
type Cert struct {
	EntryType   string
	Expiration  string
	ExpirationT time.Time
	IsExpired   bool
	Revocation  string
	RevocationT time.Time
	Serial      string
	FileName    string
	Details     *Details
}

type Details struct {
	Name             string
	CN               string
	Country          string
	State            string
	City             string
	Organisation     string
	OrganisationUnit string
	Email            string
	LocalIP          string
}

func ReadCerts(path string) ([]*Cert, error) {
	certs := make([]*Cert, 0)
	text, err := os.ReadFile(path)
	if err != nil {
		return certs, err
	}
	lines := strings.Split(trim(string(text)), "\n")
	for _, line := range lines {
		fields := strings.Split(trim(line), "\t")
		if len(fields) != 6 {
			return certs,
				fmt.Errorf("incorrect number of lines in line: \n%s\n. Expected %d, found %d",
					line, 6, len(fields))
		}
		expT, _ := time.Parse("060102150405Z", fields[1])
		expTA := time.Now().AddDate(0, 0, 36135).After(expT)      // show/hide Renew button if expired within 99 years (always show)
		logs.Debug("ExpirationT: %v, IsExpired: %v", expT, expTA) // logging
		revT, _ := time.Parse("060102150405Z", fields[2])
		c := &Cert{
			EntryType:   fields[0],
			Expiration:  fields[1],
			ExpirationT: expT,
			IsExpired:   expTA,
			Revocation:  fields[2],
			RevocationT: revT,
			Serial:      fields[3],
			FileName:    fields[4],
			Details:     parseDetails(fields[5]),
		}
		certs = append(certs, c)
	}

	return certs, nil
}

func parseDetails(d string) *Details {
	details := &Details{}
	lines := strings.Split(trim(d), "/")
	for _, line := range lines {
		if strings.Contains(line, "") {
			fields := strings.Split(trim(line), "=")
			switch fields[0] {
			case "name":
				details.Name = fields[1]
			case "CN":
				details.CN = fields[1]
			case "C":
				details.Country = fields[1]
			case "ST":
				details.State = fields[1]
			case "L":
				details.City = fields[1]
			case "O":
				details.Organisation = fields[1]
			case "OU":
				details.OrganisationUnit = fields[1]
			case "emailAddress":
				details.Email = fields[1]
			case "LocalIP":
				details.LocalIP = fields[1]
			default:
				logs.Warn(fmt.Sprintf("Undefined entry: %s", line))
			}
		}
	}
	return details
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\r\n"), "\n")
}

func CreateCertificate(name string, staticip string, passphrase string) error {
	path := state.GlobalCfg.OVConfigPath + "/pki/index.txt"
	haveip := staticip != ""
	pass := passphrase != ""
	existsError := errors.New("Error! There is already a valid or invalid certificate for the name \"" + name + "\"")
	certs, err := ReadCerts(path)
	if err != nil {
		logs.Error(err)
	}
	exists := false
	for _, v := range certs {
		if v.Details.Name == name {
			exists = true
			break
		}
	}
	Dump(certs)
	if !exists {
		if !haveip {
			staticip = "dynamic.pool"
		}
		if !pass {
			cmd := exec.Command("/bin/bash", "-c",
				fmt.Sprintf(
					"cd /opt/scripts/ && "+
						"export KEY_NAME=%s &&"+
						"./genclient.sh %s %s", name, name, staticip))
			cmd.Dir = state.GlobalCfg.OVConfigPath
			output, err := cmd.CombinedOutput()
			if err != nil {
				logs.Debug(string(output))
				logs.Error(err)
				return err
			}
			return nil
		} else {
			cmd := exec.Command("/bin/bash", "-c",
				fmt.Sprintf(
					"cd /opt/scripts/ && "+
						"export KEY_NAME=%s &&"+
						"./genclient.sh %s %s %s &&"+
						"echo 'ifconfig-push %s 255.255.255.0' > /etc/openvpn/staticclients/%s", name, name, staticip, passphrase, staticip, name))
			cmd.Dir = state.GlobalCfg.OVConfigPath
			output, err := cmd.CombinedOutput()
			if err != nil {
				logs.Debug(string(output))
				logs.Error(err)
				return err
			}
			return nil
		}
	}
	return existsError
}

func RevokeCertificate(name string, serial string) error {
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"export KEY_NAME=%s &&"+
				"./revoke.sh %s %s", name, name, serial))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func Restart() error {
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./restart.sh"))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func BurnCertificate(CN string, serial string) error {
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./rmcert.sh %s %s", CN, serial))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func RenewCertificate(name string, localip string, serial string) error {
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"export KEY_NAME=%s &&"+
				"./renew.sh %s %s %s", name, name, localip, serial))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

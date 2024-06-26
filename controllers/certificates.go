package controllers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/template"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/validation"
	"github.com/beego/beego/v2/server/web"
	clientconfig "github.com/d3vilh/openvpn-server-config/client/client-config"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

type NewCertParams struct {
	Name       string `form:"Name" valid:"Required;"`
	Staticip   string `form:"staticip"`
	Passphrase string `form:"passphrase"`
	ExpireDays string `form:"EasyRSACertExpire"`
	Email      string `form:"EasyRSAReqEmail"`
	Country    string `form:"EasyRSAReqCountry"`
	Province   string `form:"EasyRSAReqProvince"`
	City       string `form:"EasyRSAReqCity"`
	Org        string `form:"EasyRSAReqOrg"`
	OrgUnit    string `form:"EasyRSAReqOu"`
	TFAName    string `form:"TFAName"`
	TFAIssuer  string `form:"TFAIssuer"`
}

type CertificatesController struct {
	BaseController
	ConfigDir string
}

// NestPrepare sets up session data
func (c *CertificatesController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}

	// Safely retrieve session values
	isAdmin, ok := c.GetSession("IsAdmin").(bool)
	if !ok {
		c.IsAdmin = false
	} else {
		c.IsAdmin = isAdmin
	}

	userId, ok := c.GetSession("UserId").(int64)
	if !ok {
		c.Userinfo.Id = 0 // or handle the error appropriately
	} else {
		c.Userinfo.Id = userId
	}

	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "Certificates",
	}
}


// @router /certificates/:key [get]
func (c *CertificatesController) Download() {
	name := c.GetString(":key")

	cert, err := models.GetCertificateByName(name)
	if err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Redirect("/certificates?error=Certificate not found", 302)
		return
	}

	if !c.IsAdmin && int64(cert.UserId) != c.Userinfo.Id {
		c.Ctx.Output.SetStatus(403)
		c.Redirect("/certificates?error=You aren't Allowed To Download Other Certs", 302)
		return
	}

	filename := fmt.Sprintf("%s.ovpn", name)

	c.Ctx.Output.Header("Content-Type", "application/octet-stream")
	c.Ctx.Output.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	keysPath := filepath.Join(state.GlobalCfg.OVConfigPath, "pki/issued")

	cfgPath, err := c.saveClientConfig(keysPath, name)
	if err != nil {
		logs.Error(err)
		return
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		logs.Error(err)
		return
	}
	if _, err = c.Controller.Ctx.ResponseWriter.Write(data); err != nil {
		logs.Error(err)
	}
}

// @router /certificates [get]
func (c *CertificatesController) Get() {
	errorMessage := c.GetString("error")
	if errorMessage != "" {
		c.Data["Error"] = errorMessage
	}

	c.TplName = "certificates.html"
	c.showCerts()

	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg

	cfg1 := models.OVClientConfig{Profile: "default"}
	_ = cfg1.Read("Profile")
	c.Data["SettingsC"] = &cfg1

	c.Render()
}


func (c *CertificatesController) DisplayImage() {
	imageName := c.Ctx.Input.Param(":imageName")
	logs.Info("Image name: %s", imageName)
	imagePath := filepath.Join(state.GlobalCfg.OVConfigPath, "clients/", imageName+".png")
	logs.Info("Image path: %s", imagePath)

	data, err := os.ReadFile(imagePath)
	if err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Ctx.WriteString("Image not found")
		logs.Error("Error reading image file: %v", err)
		return
	}

	c.Ctx.Output.Header("Content-Type", "image/png")
	c.Ctx.Output.Body(data)
}

func (c *CertificatesController) showCerts() {
	path := filepath.Join(state.GlobalCfg.OVConfigPath, "pki/index.txt")
	certs, err := lib.ReadCerts(path)
	if err != nil {
		logs.Error(err)
	}
	lib.Dump(certs)
	c.Data["certificates"] = &certs
	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg
	cfg1 := models.OVClientConfig{Profile: "default"}
	_ = cfg1.Read("Profile")
	c.Data["SettingsC"] = &cfg1
}

// @router /certificates [post]
func (c *CertificatesController) Post() {
	logs.Info("Checking if user has certificate. UserID: %d, IsAdmin: %t", c.Userinfo.Id, c.IsAdmin)
	if !c.IsAdmin && c.userHasCert(int(c.Userinfo.Id)) {
		c.Ctx.Output.SetStatus(403)
		c.Redirect("/certificates?error=You are not allowed to create more than one certificate", 302)
		return
	}

	c.TplName = "certificates.html"
	flash := web.NewFlash()

	cParams := NewCertParams{}
	if err := c.ParseForm(&cParams); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
	} else {
		if vMap := validateCertParams(cParams); vMap != nil {
			c.Data["validation"] = vMap
		} else {
			logs.Info("Controller: Creating certificate with parameters: Name=%s, Staticip=%s, Passphrase=%s, ExpireDays=%s, Email=%s, Country=%s, Province=%s, City=%s, Org=%s, OrgUnit=%s, TFAName=%s, TFAIssuer=%s", cParams.Name, cParams.Staticip, cParams.Passphrase, cParams.ExpireDays, cParams.Email, cParams.Country, cParams.Province, strconv.Quote(cParams.City), strconv.Quote(cParams.Org), strconv.Quote(cParams.OrgUnit), cParams.TFAName, cParams.TFAIssuer)
			if err := lib.CreateCertificate(cParams.Name, cParams.Staticip, cParams.Passphrase, cParams.ExpireDays, cParams.Email, cParams.Country, cParams.Province, strconv.Quote(cParams.City), strconv.Quote(cParams.Org), strconv.Quote(cParams.OrgUnit), cParams.TFAName, cParams.TFAIssuer, int(c.Userinfo.Id)); err != nil {
				logs.Error(err)
				flash.Error(err.Error())
				flash.Store(&c.Controller)
			} else {
				flash.Success("Success! Certificate for the name \"" + cParams.Name + "\" has been created")
				flash.Store(&c.Controller)
			}
		}
	}
	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg

	c.showCerts()
}

// @router /certificates/revoke/:key [get]
func (c *CertificatesController) Revoke() {
	name := c.GetString(":key")
	
	if (!c.IsAdmin && !c.isUserCert(name)) {
		c.Ctx.Output.SetStatus(403)
		c.Redirect("/certificates?error=You're not Allowed to Revoke Other User's Cert", 302)
		return
	}

	c.TplName = "certificates.html"
	flash := web.NewFlash()
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")
	if err := lib.RevokeCertificate(name, serial, tfaname); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
	} else {
		flash.Success("Success! Certificate for the name \"" + name + "\" and serial  \"" + serial + "\" has been revoked")
		flash.Store(&c.Controller)
		
		// Reset userHasCert flag
		userID := c.GetUserIDFromCertName(name)
		lib.ResetUserCertStatus(userID)
	}
	c.Redirect(c.URLFor("CertificatesController.Get"), 302)
}


// @router /certificates/restart [get]
func (c *CertificatesController) Restart() {
	lib.Restart()
	c.Redirect(c.URLFor("CertificatesController.Get"), 302)
}

// @router /certificates/burn/:key/:serial/:tfaname [get]
func (c *CertificatesController) Burn() {
	name := c.GetString(":key")
	
	if !c.IsAdmin && !c.isUserCert(name) {
		c.Ctx.Output.SetStatus(403)
		c.Redirect("/certificates?error=You're not Allowed to Delete Other User's Cert", 302)
		return
	}

	c.TplName = "certificates.html"
	flash := web.NewFlash()
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")
	logs.Info("Controller: Burning certificate with parameters: CN=%s, serial=%s, tfaname=%s", name, serial, tfaname)
	if err := lib.BurnCertificate(name, serial, tfaname); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
	} else {
		flash.Success("Success! Certificate for the name \"" + name + "\" and serial  \"" + serial + "\" has been removed")
		flash.Store(&c.Controller)
		
		// Reset userHasCert flag
		userID := c.GetUserIDFromCertName(name)
		lib.ResetUserCertStatus(userID)
	}
	c.Redirect(c.URLFor("CertificatesController.Get"), 302)
}


// @router /certificates/renew/:key [get]
func (c *CertificatesController) Renew() {
	name := c.GetString(":key")

	cert, err := models.GetCertificateByName(name)
	if err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Redirect("/certificates?error=You're not Allowed to Renew Other User's Cert", 302)
		return
	}

	if !c.IsAdmin && int64(cert.UserId) != c.Userinfo.Id {
		c.Ctx.Output.SetStatus(403)
		c.Redirect("/certificates?error=Permission denied", 302)
		return
	}

	c.TplName = "certificates.html"
	flash := web.NewFlash()
	localip := c.GetString(":localip")
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")
	if err := lib.RenewCertificate(name, localip, serial, tfaname); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
	} else {
		flash.Success("Success! Certificate for the name \"" + name + "\" and IP \"" + localip + "\" and Serial \"" + serial + "\" has been renewed")
		flash.Store(&c.Controller)
	}
	c.Redirect(c.URLFor("CertificatesController.Get"), 302)
}



func validateCertParams(cert NewCertParams) map[string]map[string]string {
	valid := validation.Validation{}
	b, err := valid.Valid(&cert)
	if err != nil {
		logs.Error(err)
		return nil
	}
	if !b {
		return lib.CreateValidationMap(valid)
	}
	return nil
}

func (c *CertificatesController) saveClientConfig(keysPath string, name string) (string, error) {
	cfg := clientconfig.New()
	keysPathCa := filepath.Join(state.GlobalCfg.OVConfigPath, "pki")

	ovClientConfig := &models.OVClientConfig{Profile: "default"}
	if err := ovClientConfig.Read("Profile"); err != nil {
		return "", err
	}
	cfg.ServerAddress = ovClientConfig.ServerAddress
	cfg.OpenVpnServerPort = ovClientConfig.OpenVpnServerPort
	cfg.AuthUserPass = ovClientConfig.AuthUserPass
	cfg.ResolveRetry = ovClientConfig.ResolveRetry
	cfg.OVClientUser = ovClientConfig.OVClientUser
	cfg.OVClientGroup = ovClientConfig.OVClientGroup
	cfg.PersistTun = ovClientConfig.PersistTun
	cfg.PersistKey = ovClientConfig.PersistKey
	cfg.RemoteCertTLS = ovClientConfig.RemoteCertTLS
	cfg.RedirectGateway = ovClientConfig.RedirectGateway
	cfg.Proto = ovClientConfig.Proto
	cfg.Auth = ovClientConfig.Auth
	cfg.Cipher = ovClientConfig.Cipher
	cfg.Device = ovClientConfig.Device
	cfg.AuthNoCache = ovClientConfig.AuthNoCache
	cfg.TlsClient = ovClientConfig.TlsClient
	cfg.Verbose = ovClientConfig.Verbose
	cfg.CustomConfOne = ovClientConfig.CustomConfOne
	cfg.CustomConfTwo = ovClientConfig.CustomConfTwo
	cfg.CustomConfThree = ovClientConfig.CustomConfThree

	ca, err := os.ReadFile(filepath.Join(keysPathCa, "ca.crt"))
	if err != nil {
		return "", err
	}
	cfg.Ca = string(ca)

	ta, err := os.ReadFile(filepath.Join(keysPathCa, "ta.key"))
	if err != nil {
		return "", err
	}
	cfg.Ta = string(ta)

	cert, err := os.ReadFile(filepath.Join(keysPath, name+".crt"))
	if err != nil {
		return "", err
	}
	cfg.Cert = string(cert)

	keysPathKey := filepath.Join(state.GlobalCfg.OVConfigPath, "pki/private")
	key, err := os.ReadFile(filepath.Join(keysPathKey, name+".key"))
	if err != nil {
		return "", err
	}
	cfg.Key = string(key)

	serverConfig := models.OVConfig{Profile: "default"}
	_ = serverConfig.Read("Profile")
	cfg.Port = serverConfig.Port

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "clients", name+".ovpn")
	if err := SaveToFile(filepath.Join(c.ConfigDir, "openvpn-client-config.tpl"), cfg, destPath); err != nil {
		logs.Error(err)
		return "", err
	}

	return destPath, nil
}

func GetText(tpl string, c clientconfig.Config) (string, error) {
	t := template.New("config")
	t, err := t.Parse(tpl)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	err = t.Execute(buf, c)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func SaveToFile(tplPath string, c clientconfig.Config, destPath string) error {
	tpl, err := os.ReadFile(tplPath)
	if err != nil {
		return err
	}

	str, err := GetText(string(tpl), c)
	if err != nil {
		return err
	}

	return os.WriteFile(destPath, []byte(str), 0644)
}

// isUserCert checks if the certificate belongs to the logged-in user
func (c *CertificatesController) isUserCert(certName string) bool {
	return lib.IsUserCert(certName, int(c.Userinfo.Id))
}

func (c *CertificatesController) userHasCert(userID int) bool {
	logs.Info("Checking if user has a certificate. User ID: %d", userID)
	hasCert := lib.UserHasCert(userID)
	logs.Info("User ID %d has certificate: %t", userID, hasCert)
	return hasCert
}
// Helper function to get user ID from certificate name
func (c *CertificatesController) GetUserIDFromCertName(certName string) int {
	cert, err := models.GetCertificateByName(certName)
	if err != nil {
		logs.Error("Failed to get certificate by name: %v", err)
		return 0
	}
	return cert.UserId
}

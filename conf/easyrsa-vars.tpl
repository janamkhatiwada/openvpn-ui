set_var EASYRSA_DN           "{{ .EasyRSADN }}"
set_var EASYRSA_REQ_COUNTRY  "{{ .EasyRSAReqCountry }}"
set_var EASYRSA_REQ_PROVINCE "{{ .EasyRSAReqProvince }}"
set_var EASYRSA_REQ_CITY     "{{ .EasyRSAReqCity }}"
set_var EASYRSA_REQ_ORG      "{{ .EasyRSAReqOrg }}"
set_var EASYRSA_REQ_EMAIL    "{{ .EasyRSAReqEmail }}"
set_var EASYRSA_REQ_OU       "{{ .EasyRSAReqOu }}"
set_var EASYRSA_REQ_CN       "{{ .EasyRSAReqCn }}"
set_var EASYRSA_KEY_SIZE     {{ .EasyRSAKeySize }}
set_var EASYRSA_CA_EXPIRE    {{ .EasyRSACaExpire }}
set_var EASYRSA_CERT_EXPIRE  {{ .EasyRSACertExpire }}
set_var EASYRSA_CERT_RENEW   {{ .EasyRSACertRenew }}
set_var EASYRSA_CRL_DAYS     {{ .EasyRSACrlDays }}
# Auto generated by OpenVPN-UI v.0.9
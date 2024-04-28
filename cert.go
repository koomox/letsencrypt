package letsencrypt

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
)

var (
	DigiCertBaltimoreRoot = []byte(`-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y
ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy
VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr
mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr
IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK
mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu
XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy
dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye
jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1
BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92
9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx
jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0
Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz
ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS
R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp
-----END CERTIFICATE-----`)
	CloudflareIncECCCA3 = []byte(`-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIQCjeHZF5ftIwiTv0b7RQMPDANBgkqhkiG9w0BAQsFADBa
MQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJl
clRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTIw
MDEyNzEyNDgwOFoXDTI0MTIzMTIzNTk1OVowSjELMAkGA1UEBhMCVVMxGTAXBgNV
BAoTEENsb3VkZmxhcmUsIEluYy4xIDAeBgNVBAMTF0Nsb3VkZmxhcmUgSW5jIEVD
QyBDQS0zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEua1NZpkUC0bsH4HRKlAe
nQMVLzQSfS2WuIg4m4Vfj7+7Te9hRsTJc9QkT+DuHM5ss1FxL2ruTAUJd9NyYqSb
16OCAWgwggFkMB0GA1UdDgQWBBSlzjfq67B1DpRniLRF+tkkEIeWHzAfBgNVHSME
GDAWgBTlnVkwgkdYzKz6CFQ2hns6tQRN8DAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l
BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYI
KwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
b20wOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL09t
bmlyb290MjAyNS5jcmwwbQYDVR0gBGYwZDA3BglghkgBhv1sAQEwKjAoBggrBgEF
BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMAgGBmeBDAECAjAIBgZngQwBAgMwDQYJKoZIhvcNAQELBQADggEB
AAUkHd0bsCrrmNaF4zlNXmtXnYJX/OvoMaJXkGUFvhZEOFp3ArnPEELG4ZKk40Un
+ABHLGioVplTVI+tnkDB0A+21w0LOEhsUCxJkAZbZB2LzEgwLt4I4ptJIsCSDBFe
lpKU1fwg3FZs5ZKTv3ocwDfjhUkV+ivhdDkYD7fa86JXWGBPzI6UAPxGezQxPk1H
goE6y/SJXQ7vTQ1unBuCJN0yJV0ReFEQPaA1IwQvZW+cwdFD19Ae8zFnWSfda9J1
CZMRJCQUzym+5iPDuI9yP+kHyCREU3qzuWFloUwOxkgAyXVjBYdwRVKD05WdRerw
6DEdfgkfCv4+3ao8XnTSrLE=
-----END CERTIFICATE-----`)
	customCertRoot = []byte(`-----BEGIN CERTIFICATE-----
MIIFMTCCAxkCFErqFFvcK1yEoHxTHWzFJCF8hHBfMA0GCSqGSIb3DQEBCwUAMFUx
CzAJBgNVBAYTAlVTMQwwCgYDVQQIDANMQVgxFDASBgNVBAcMC0xvcyBBbmdlbGVz
MQowCAYDVQQKDAFYMQowCAYDVQQLDAFYMQowCAYDVQQDDAFYMB4XDTI0MDQyODA4
MDA1MVoXDTI0MDUyODA4MDA1MVowVTELMAkGA1UEBhMCVVMxDDAKBgNVBAgMA0xB
WDEUMBIGA1UEBwwLTG9zIEFuZ2VsZXMxCjAIBgNVBAoMAVgxCjAIBgNVBAsMAVgx
CjAIBgNVBAMMAVgwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC3mvdj
qYY8ijhzbl0h3JK1FJ58m8juC1k3w6UAT2y/o2VmymiBHidaKAXQvoJQf50tAoJY
2atUtw3ViwTOHMAEVir9U2XfF+7ixC55F0fiI/XqFcKVMIsotTYBARWg7JHplYRn
d7lbpA31hcJoHykCkYcP61ktpwgASXToEaFd9dJlYWM6fH709SQ2+6ARQH/DF4Ku
awUECx31PdWnWvGWCuzfV5J3HY9ivlDiG2qYCn0JAKXtt9jlFp5lYQ/jhzfZJuFq
fCX++Zs+f+t8TIpah0bjlKtF8mZA9dq614Gqj0NMls4Rq3yvwyi1bt3ohGJi+hna
ActAhdWgNnSIILblYuXthu5E95mYMXUArVjOl23mX9E/L+5MLdG+94lwYHFxDDnc
nSv8okWYsx126SEZU1Cf6Zit3acW4XvQrWDiZz5VqONrmRkI18NdP88ocQIClF/T
0zADxnVnBPyppOClGKQWwPJcvf056ClVpXxd5EknD2Olr626oJaRDaEs0PrhOTLY
mUk1cj9Z0Qvgoq2HS4nbHDZvECJDP1Ih2br8W9eTCT8JjVmdo4A+G2jlfZk2xqFV
oVlWRQkVjfXb7ygSJlncFHGWEvh3kiNFnQs9iL0gu2W0W2Gq1RoUvbXlmxwe+iIK
tcA3P65bjGLtesvh86XbelbelUHQebreoH+18wIDAQABMA0GCSqGSIb3DQEBCwUA
A4ICAQBgw42cPbSpq2G/W3mNCibktZQnz5f4aIf69i7DKEumHDTvdlY02uUN60DX
XGBD8R686h3Vfj1CvfabI/kkBO0nKU67BN5CsmoDuQuNEMgWewSIIhsczmTgVq73
H+c13cxNeZ9E4LfuGydLSSYIu55hjPRIs+sBNymYEnWff8ZTLAT+6d4WFxjcDvIk
B5M8XC8mqTx83+whGzBek7QupbI+zMkEdwTFQQENHQo5dhnnpsEKJdOPTyFO5CSc
kmNarWVzQnwpfv9zddT7mFNMsCy6/4ZDf37pFd+wiw8C5Ws6aSZVaPw67DzyS0Mf
ADfziYZ1dmPiS130pIaSRXnH2PSMxq4OgQaJvweQFeLPANU/KtrDHsPoq+zcyey1
uG8sx2z49SeUlJc0b2p6r0QWPFdgi8417brj4IZ9C2w97C45EpnG+96JVU9tHHtA
w7cJcMJYATBgIfqSQwScMyZd1f7XHoGCGiXeLVNgLcKh3BJqh1nGjeDWPOUVt9dN
Em/NQm2u+U13FfNDgvXIolZPmIZW+2hvueE2QUhCO8pimcatX5Ac15VcoiXfvuux
UVTmsdfat/FeEZxZsTr/OEt6JbEcYiXve/zRu7u0b5SAxhMU09+p0a22W6oG3i6k
PEM+YmMKpmIBlicO/cBX84JyL7jQ3hRyltdK/sEFJj0NAUR4sg==
-----END CERTIFICATE-----`)
)

func init() {
	certificates = append(certificates, DigiCertBaltimoreRoot, CloudflareIncECCCA3, customCertRoot)
}

func loadCertPool(certsPem ...[]byte) (pool *x509.CertPool) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	certs, err := GetCloudflareRootCA()
	if err == nil {
		for _, ca := range certs {
			pool.AddCert(ca)
		}
	}
	for _, pem := range certsPem {
		pool.AppendCertsFromPEM(pem)
	}

	return
}

func CertPool() *x509.CertPool {
	return loadCertPool(certificates...)
}

func GetDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		return path.Join(dir, "acme")
	}
	return ".acme"
}

func TLSConfig() (tlsCfg *tls.Config) {
	tlsCfg = &tls.Config{}
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.RootCAs = loadCertPool(certificates...)

	return
}
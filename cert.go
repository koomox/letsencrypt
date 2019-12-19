package letsencrypt

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
)

var (
	// https://letsencrypt.org/certs/trustid-x3-root.pem.txt
	trustidX3RootCa = []byte(`-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----`)

	// https://letsencrypt.org/certs/isrg-root-ocsp-x1.pem.txt
	isrgRootOcspX1Ca = []byte(`-----BEGIN CERTIFICATE-----
MIIEtjCCAp6gAwIBAgIRAOSLLZlzkiCW3s5KSK7GfFEwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTIwMDQw
WhcNMjAwNjA0MTIwMDQwWjBUMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxGjAYBgNVBAMTEUlTUkcgUm9vdCBP
Q1NQIFgxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuw0cR9Li4+M+
aIJixENnV4PM9N8nAxwWsM/7PzV/766q/1PKA8jB4OykscNkK9XCblOElSzXSQJx
BrpckIquoydslakPvaB4HLj3cx8EJP4tEyXRDt415uZs9LWFSoplSLBFNC2gMfL7
WYxPqcoOagU+amCVSEDK85oILqnZ27FJrU2hQGOF/lWDa1y1YiIp9e2+ryFOUn1w
AVWQdnOyovh6suBnjCcR+269q6Xtf3/fUHjqnOgO7e8XMDy69MygLltOzDxI0/VA
21EL1kBoC2ckgorVASrKByaPS9o6p2bYcHZ3FC/3g+tv6pCiFZt+e4YMBnYVyAYC
miJVv7PFtQIDAQABo4GHMIGEMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBQfuyfyJnprzPH1dNmWK34Z7MMcIzATBgNVHSUEDDAKBggrBgEF
BQcDCTAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAPBgkrBgEFBQcw
AQUEAgUAMA0GCSqGSIb3DQEBCwUAA4ICAQB6baTUbmQI6I2/BPB2gDsxRMSeppGM
g5lcDQE4aP7oPDcRq+S+6LuuwVjj67UZfJqczCgcJRcG/6kMjBq7jcg6DmhVP8V6
9f47vri57ikQLQge4yibUkMpmaT+IaUKklSQhA2ZAsFRd638DW+wNlkp8FpORz0K
1BymHOYq6xpRyEW5piZhi7ZCrR4x1k7uGChpYP+X79xmht4FUpJRbVuHtnjjZTGH
BIrZj+n2iIPTrjBn5fpfmOb+ABlV9ovvxUYql6cpQmvYzelvoA7tZ0EJf0nwF+FS
orbSX1CiTLXGnvoGun84UXOLY2Thgf8SVGESaeR9cQJBHi8w1ksK++36SECauTNP
hcegMGEdxlHPc3yrP3EcC+rqNdLRWCNkSnnLXFxWlk9JJayzOuF/HDObtJB54AEp
M7ly58PdQD1MGQ4GBFTsXN28sqfzpwl/RQGmeHz7EVPb5hHoW8z+CwUtbTrNhYNc
FMnjGFnZCHsbTjuOMGN4koyZtpRnhpHs0LgmsYeofiECtbKUvSL1DB1DTkjitM7s
qjFfubGSKwAGJZFLi0EwLzUe+DZvYagZBT/Upp/Ush9ImwzKZirqVfA6/qgFOLST
NdCsat0uo+FX1klsPm6enps9WCOFpkIppbf6WAUv+myiDOY2jh6GpVsc07qDVZFG
89JKdHDn7q5TsQ==
-----END CERTIFICATE-----`)

	// PEM files for root certificates of LetsEncrypt Intermediary and Root.
	letsEncryptIntermediaryCa = []byte(`-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`)

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
	return loadCertPool(trustidX3RootCa, isrgRootOcspX1Ca, letsEncryptIntermediaryCa)
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
	tlsCfg.RootCAs = loadCertPool(trustidX3RootCa, isrgRootOcspX1Ca, letsEncryptIntermediaryCa)

	return
}
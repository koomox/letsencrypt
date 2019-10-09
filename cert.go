package letsencrypt

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
)

var (
	rootCApem = []byte(`-----BEGIN CERTIFICATE-----
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

	subCApem = []byte(`-----BEGIN CERTIFICATE-----
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

	kCApem = []byte(`-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIJAMcX+jkUFL9CMA0GCSqGSIb3DQEBCwUAMDgxCzAJBgNV
BAYTAkNOMREwDwYDVQQKDAhLb3ggSW5jLjEWMBQGA1UEAwwNS294IEdsb2JhbCBD
QTAeFw0xNzA5MDIxMDA2MzFaFw00NzA4MjYxMDA2MzFaMDgxCzAJBgNVBAYTAkNO
MREwDwYDVQQKDAhLb3ggSW5jLjEWMBQGA1UEAwwNS294IEdsb2JhbCBDQTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwVEvHDD2Nj2Do+U7++ZjEsn7Dx
GGb8Tf8wTKwHU2+XB80GIN+OYljL6lCNqBxzbfZryOd5DX4fJUhGTaurIf61xFAp
3kNH7L4WBGQCrYByAkr5Q6rG7GenbtUlTDjLvyU6TtIg3b0jGGNqI1pckEOzKITd
7oS/G2uG20X7GZPjKJ0yFTqhbP6QqGpVAWmWvaOuXq45J5ECFMtkViXL/BDKlWEc
97HRYfiG1ZAD3uPuaqjsX2ONlAT629LVuExhfoTAZghcpz9sZpWUHZQIKEiowI/X
K5aDgUG70DVdycucKv9ARv7N/pMF/1q7SoXbc5H4LOM4JOhhvmQWB71biBMCAwEA
AaNQME4wHQYDVR0OBBYEFEemYeoTKgBH9ylauDDAU/oHCvGyMB8GA1UdIwQYMBaA
FEemYeoTKgBH9ylauDDAU/oHCvGyMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKrnEFvd/ow9Hg78KocWjbWfy0iKHnOkvff/L3+4fk/mbuymHHM6jfe5
k9geRMVsBcdS4SF7efisKBAx8lZ3fUTI3C3Ab+pBWLGVm3bEPGwENJcl245YXmUb
+fCjanJwIW1kieo1fNQFbygJJLAkXLqRzgel6OJE8f1srAltyawDwt6eSCYSdG5t
Y4DZRyQlhef53Ba5x6NkMHMHUbFaJ7YFNaaAtFmfSwwsuiNO+4lukmqxUOFZ99rj
dZIzXjFjimvd2xzguT7/4YAQq9ArtFWKmAQkTytdGVhkQQMH5WjLinstidlppQJO
KTsoeRdCjuO4Sa0Q/5wm81/4wxEIIt4=
-----END CERTIFICATE-----`)

	mCApem = []byte(`-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIJAM2U4oaX5uvAMA0GCSqGSIb3DQEBCwUAMDgxCzAJBgNV
BAYTAkNOMREwDwYDVQQKDAhNb3ggSW5jLjEWMBQGA1UEAwwNTW94IEdsb2JhbCBD
QTAeFw0xNzA4MzAxNDIwMTVaFw00NzA4MjMxNDIwMTVaMDgxCzAJBgNVBAYTAkNO
MREwDwYDVQQKDAhNb3ggSW5jLjEWMBQGA1UEAwwNTW94IEdsb2JhbCBDQTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM1u0V9HkdRY2x3KIXCILGDynq4Z
SE0SuCHgWH8ROpGqyG9r3wM9xrH56mOPtfnjPkthvCrX+TYiMQT8+AV37w7u9enN
ZTxwTOwwHDFqyHWV4xQdcFpgbnmGH6LwcnNL75CwOzGyKp7haM579SnBZn4EH8Na
1bSBLKXWjCDwPxQDkWwVjyPPXBUG93eT0vbMfRsx7PJkZx7ERzhnz+wE1Uv3Yqs4
N+L/blWcQQJFWzp1D58aWiEODrA7ZKzA6wchhfVFbSLxzE9/XPZjIKP9nW4dg6e6
epZf5zL9HLRNWx1zXZ4tZSZWvf5OO2YyyudQ0MhuQbB5iqkqUM62FMCJjOUCAwEA
AaNQME4wHQYDVR0OBBYEFN6DqIT6LZFTUeG1tkaO0UajEOHDMB8GA1UdIwQYMBaA
FN6DqIT6LZFTUeG1tkaO0UajEOHDMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAAlqDkbZAl9PbuMa5mHAnRU9Vg5putG+cI9ePmH2uDEUJCXgpjQcyH72
p+6tBNU+n72M6uO+xNoaU74FJhbr32WJFKnlobZ0COsdG0DKzndkMLqim/QG6cUQ
yNgBTYXx4g+YcRllQIXWuvWKNx3aX/C3JWXOZKLhh8uoCJ6BaVrVwQ61j55YhKAP
RtNiAMhFPPxCh8vVB1vGruLXdsKSbB8RJV2dHtp3DYjbDmACRnCMR3b2K7Qa0Db5
d87sea2mBzLEVFTT7RcgA21vTgk5qBKEtd/Llx9CcUfEn6ewgpa9JMdjD6pA+5HI
T4OU/RX7VbZvL5DB/L/gW0XoYwO4SKg=
-----END CERTIFICATE-----`)
)

func loadCertPool(certsPem ...[]byte) (pool *x509.CertPool) {
	pool = x509.NewCertPool()
	for _, pem := range certsPem {
		pool.AppendCertsFromPEM(pem)
	}

	return
}

func CertPool() *x509.CertPool {
	return loadCertPool(rootCApem, subCApem, kCApem, mCApem)
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
	tlsCfg.RootCAs = loadCertPool(rootCApem, subCApem, kCApem, mCApem)

	return
}

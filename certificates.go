package letsencrypt

var (
	// https://letsencrypt.org/certs/isrgrootx1.pem
	isrgrootx1 = []byte(`-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/isrg-root-x1-cross-signed.pem
	isrgrootx1crosssigned = []byte(`-----BEGIN CERTIFICATE----- 
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
`)
	// https://letsencrypt.org/certs/isrg-root-x2.pem
	isrgrootx2 = []byte(`-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem
	isrgrootx2crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEYDCCAkigAwIBAgIQB55JKIY3b9QISMI/xjHkYzANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yMDA5MDQwMDAwMDBa
Fw0yNTA5MTUxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5l
dCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgy
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0H
ttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7
AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR8Qpau3ktIO/qS+J6Mz22LqXI3lTAf
BgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQw
IgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wJwYDVR0fBCAwHjAc
oBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzAiBgNVHSAEGzAZMAgGBmeBDAEC
ATANBgsrBgEEAYLfEwEBATANBgkqhkiG9w0BAQsFAAOCAgEAG38lK5B6CHYAdxjh
wy6KNkxBfr8XS+Mw11sMfpyWmG97sGjAJETM4vL80erb0p8B+RdNDJ1V/aWtbdIv
P0tywC6uc8clFlfCPhWt4DHRCoSEbGJ4QjEiRhrtekC/lxaBRHfKbHtdIVwH8hGR
Ib/hL8Lvbv0FIOS093nzLbs3KvDGsaysUfUfs1oeZs5YBxg4f3GpPIO617yCnpp2
D56wKf3L84kHSBv+q5MuFCENX6+Ot1SrXQ7UW0xx0JLqPaM2m3wf4DtVudhTU8yD
ZrtK3IEGABiL9LPXSLETQbnEtp7PLHeOQiALgH6fxatI27xvBI1sRikCDXCKHfES
c7ZGJEKeKhcY46zHmMJyzG0tdm3dLCsmlqXPIQgb5dovy++fc5Ou+DZfR4+XKM6r
4pgmmIv97igyIintTJUJxCD6B+GGLET2gUfA5GIy7R3YPEiIlsNekbave1mk7uOG
nMeIWMooKmZVm4WAuR3YQCvJHBM8qevemcIWQPb1pK4qJWxSuscETLQyu/w4XKAM
YXtX7HdOUM+vBqIPN4zhDtLTLxq9nHE+zOH40aijvQT2GcD5hq/1DhqqlWvvykdx
S2McTZbbVSMKnQ+BdaDmQPVkRgNuzvpqfQbspDQGdNpT2Lm4xiN9qfgqLaSCpi4t
EcrmzTFYeYXmchynn9NM0GbQp7s=
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-r3.pem
	letsencryptr3 = []byte(`-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem
	letsencryptr3crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMUpMghjISpDBbN3zANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0MFoXDTIxMDkyOTE5MjE0MFow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwIVKMz2oJTTDxLs
jVWSw/iC8ZmmekKIp10mqrUrucVMsa+Oa/l1yKPXD0eUFFU1V4yeqKI5GfWCPEKp
Tm71O8Mu243AsFzzWTjn7c9p8FoLG77AlCQlh/o3cbMT5xys4Zvv2+Q7RVJFlqnB
U840yFLuta7tj95gcOKlVKu2bQ6XpUA0ayvTvGbrZjR8+muLj1cpmfgwF126cm/7
gcWt0oZYPRfH5wm78Sv3htzB2nFd1EbjzK0lwYi8YGd1ZrPxGPeiXOZT/zqItkel
/xMY6pgJdz+dU/nPAeX1pnAXFK9jpP+Zs5Od3FOnBv5IhR2haa4ldbsTzFID9e1R
oYvbFQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYf
r52LFMLGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEA2UzgyfWEiDcx27sT4rP8i2tiEmxYt0l+PAK3qB8oYevO4C5z70kH
ejWEHx2taPDY/laBL21/WKZuNTYQHHPD5b1tXgHXbnL7KqC401dk5VvCadTQsvd8
S8MXjohyc9z9/G2948kLjmE6Flh9dDYrVYA9x2O+hEPGOaEOa1eePynBgPayvUfL
qjBstzLhWVQLGAkXXmNs+5ZnPBxzDJOLxhF2JIbeQAcH5H0tZrUlo5ZYyOqA7s9p
O5b85o3AM/OJ+CktFBQtfvBhcJVd9wvlwPsk+uyOy2HI7mNxKKgsBTt375teA2Tw
UdHkhVNcsAKX1H7GNNLOEADksd86wuoXvg==
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-e1.pem
	letsencrypte1 = []byte(`-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-r4.pem
	letsencryptr4 = []byte(`-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAIp5IlCr5SxSbO7Pf8lC3WIwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCzKNx3KdPnkb7ztwoAx/vyVQslImNTNq/pCCDfDa8oPs3Gq1e2naQlGaXS
Mm1Jpgi5xy+hm5PFIEBrhDEgoo4wYCVg79kaiT8faXGy2uo/c0HEkG9m/X2eWNh3
z81ZdUTJoQp7nz8bDjpmb7Z1z4vLr53AcMX/0oIKr13N4uichZSk5gA16H5OOYHH
IYlgd+odlvKLg3tHxG0ywFJ+Ix5FtXHuo+8XwgOpk4nd9Z/buvHa4H6Xh3GBHhqC
VuQ+fBiiCOUWX6j6qOBIUU0YFKAMo+W2yrO1VRJrcsdafzuM+efZ0Y4STTMzAyrx
E+FCPMIuWWAubeAHRzNl39Jnyk2FAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0xivZUpkYmMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCJbu5CalWO+H+Az0lmIG14DXmlYHQE
k26umjuCyioWs2icOlZznPTcZvbfq02YPHGTCu3ctggVDULJ+fwOxKekzIqeyLNk
p8dyFwSAr23DYBIVeXDpxHhShvv0MLJzqqDFBTHYe1X5X2Y7oogy+UDJxV2N24/g
Z8lxG4Vr2/VEfUOrw4Tosl5Z+1uzOdvTyBcxD/E5rGgTLczmulctHy3IMTmdTFr0
FnU0/HMQoquWQuODhFqzMqNcsdbjANUBwOEQrKI8Sy6+b84kHP7PtO+S4Ik8R2k7
ZeMlE1JmxBi/PZU860YlwT8/qOYToCHVyDjhv8qutbf2QnUl3SV86th2I1QQE14s
0y7CdAHcHkw3sAEeYGkwCA74MO+VFtnYbf9B2JBOhyyWb5087rGzitu5MTAW41X9
DwTeXEg+a24tAeht+Y1MionHUwa4j7FB/trN3Fnb/r90+4P66ZETVIEcjseUSMHO
w6yqv10/H/dw/8r2EDUincBBX3o9DL3SadqragkKy96HtMiLcqMMGAPm0gti1b6f
bnvOdr0mrIVIKX5nzOeGZORaYLoSD4C8qvFT7U+Um6DMo36cVDNsPmkF575/s3C2
CxGiCPQqVxPgfNSh+2CPd2Xv04lNeuw6gG89DlOhHuoFKRlmPnom+gwqhz3ZXMfz
TfmvjrBokzCICA==
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem
	letsencryptr4crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMlO+Rkt3exI9CKgjANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0NVoXDTIxMDkyOTE5MjE0NVow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlI0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsyjcdynT55G+87cK
AMf78lULJSJjUzav6Qgg3w2vKD7NxqtXtp2kJRml0jJtSaYIuccvoZuTxSBAa4Qx
IKKOMGAlYO/ZGok/H2lxstrqP3NBxJBvZv19nljYd8/NWXVEyaEKe58/Gw46Zm+2
dc+Ly6+dwHDF/9KCCq9dzeLonIWUpOYANeh+TjmBxyGJYHfqHZbyi4N7R8RtMsBS
fiMeRbVx7qPvF8IDqZOJ3fWf27rx2uB+l4dxgR4aglbkPnwYogjlFl+o+qjgSFFN
GBSgDKPltsqztVUSa3LHWn87jPnn2dGOEk0zMwMq8RPhQjzCLllgLm3gB0czZd/S
Z8pNhQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0x
ivZUpkYmMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEAN4CpgPmK2C5pq/RdV9gEdWcvPnPfT9ToucrAMTcn//wyWBWF2wG4
hvPBQxxuqPECZsi4nLQ45VJpyC1NDd0GqGQIMqNdC4N4TLDtd7Yhy8v5JsfEMUbb
6xW4sKeeeKy3afOkel60Xg1/7ndSmppiHqdh+TdJML1hptRgdxGiB8LMpHuW/oM8
akfyt4TkBhA8+Wu8MM6dlJyJ7nHBVnEUFQ4Ni+GzNC/pQSL2+Y9Mq4HHIk2ZFy0W
B8KsVwdeNrERPL+LjhhLde1Et0aL9nlv4CqwXHML2LPgk38j/WllbQ/8HRd2VpB+
JW6Z8JNhcnuBwATHMCeJVCFapoZsPfQQ6Q==
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-e2.pem
	letsencrypte2 = []byte(`-----BEGIN CERTIFICATE-----
MIICxjCCAkygAwIBAgIQTtI99q9+x/mwxHJv+VEqdzAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw0y
NTA5MTUxNjAwMDBaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABCOaLO3lixmN
YVWex+ZVYOiTLgi0SgNWtU4hufk50VU4Zp/LbBVDxCsnsI7vuf4xp4Cu+ETNggGE
yBqJ3j8iUwe5Yt/qfSrRf1/D5R58duaJ+IvLRXeASRqEL+VkDXrW3qOCAQgwggEE
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUbZkq9U0C6+MRwWC6km+NPS7x
6kQwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5UwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wIgYDVR0gBBswGTAIBgZn
gQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZIzj0EAwMDaAAwZQIxAPJCN9qpyDmZ
tX8K3m8UYQvK51BrXclM6WfrdeZlUBKyhTXUmFAtJw4X6A0x9mQFPAIwJa/No+KQ
UAM1u34E36neL/Zba7ombkIOchSgx1iVxzqtFWGddgoG+tppRPWhuhhn
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/letsencryptauthorityx1.pem
	letsencryptauthorityx1 = []byte(`-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAOeTkL6SBwNJGF95dYHlyoMwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTIwMDIw
WhcNMjAwNjA0MTIwMDIwWjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AGvM/XGv8yafGRGMPP6hnggoI9DGWGf4l0mzjBhuCkDVqoG/7rsH1ytzteePxiA3
7kqSBo0fXu5GmbWOw09GpwPYyAAY0iWOMU6ybrTJHS466Urzoe/4IwLQoQc219EK
lh+4Ugu1q4KxNY1qMDA/1YX2Qm9M6AcAs1UvZKHSpJQAbsYrbN6obNoUGOeG6ONH
Yr8KRQz5FMfZYcA49fmdDTwKn/pyLOkJFeA/dm/oP99UmKCFoeOa5w9YJr2Vi7ic
Xd59CU8mprWhxFXnma1oU3T8ZNovjib3UHocjlEJfNbDy9zgKTYURcMVweo1dkbH
NbLc5mIjIk/kJ+RPD+chR+gJjy3Gh9xMNkDrZQKfsIO93hxTsZMmgZQ4c+vujC1M
jSak+Ai87YZeYQPh1fCGMSTno5III37DUCtIn8BJxJixuPeOMKsjLLD5AtMVy0fp
d19lcUek4bjDY8/Ujb5/wfn2+Kk7z72SxWdekjtHOWBmKxqq8jDuuMw4ymg1g5n7
R7TZ/Y3y4bTpWUDkBHFo03xNM21wBFDIrCZZeVhvDW4MtT6+Ass2bcpoHwYcGol2
gaLDa5k2dkG41OGtXa0fY+TjdryY4cOcstJUKjv2MJku4yaTtjjECX1rJvFLnqYe
wC+FmxjgWPuyRNuLDAWK30mmpcJZ3CmD6dFtAi4h7H37
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem
	letsencryptx1crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAJgT9HUT5XULQ+dDHpceRL0wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjMzMzZaFw0yMDEwMTkyMjMzMzZa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJzTDPBa5S5Ht3JdN4OzaGMw6tc1Jhkl4b2+NfFwki+3uEtB
BaupnjUIWOyxKsRohwuj43Xk5vOnYnG6eYFgH9eRmp/z0HhncchpDpWRz/7mmelg
PEjMfspNdxIknUcbWuu57B43ABycrHunBerOSuu9QeU2mLnL/W08lmjfIypCkAyG
dGfIf6WauFJhFBM/ZemCh8vb+g5W9oaJ84U/l4avsNwa72sNlRZ9xCugZbKZBDZ1
gGusSvMbkEl4L6KWTyogJSkExnTA0DHNjzE4lRa6qDO4Q/GxH8Mwf6J5MRM9LTb4
4/zyM2q5OTHFr8SNDR1kFjOq+oQpttQLwNh9w5MCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUqEpqYwR93brm0Tm3
pkVl7/Oo7KEwDQYJKoZIhvcNAQELBQADggEBANHIIkus7+MJiZZQsY14cCoBG1hd
v0J20/FyWo5ppnfjL78S2k4s2GLRJ7iD9ZDKErndvbNFGcsW+9kKK/TnY21hp4Dd
ITv8S9ZYQ7oaoqs7HwhEMY9sibED4aXw09xrJZTC9zK1uIfW6t5dHQjuOWv+HHoW
ZnupyxpsEUlEaFb+/SCI4KCSBdAsYxAcsHYI5xxEI4LutHp6s3OT2FuO90WfdsIk
6q78OMSdn875bNjdBYAqxUp2/LEIHfDBkLoQz0hFJmwAbYahqKaLn73PAAm1X2kj
f1w8DdnkabOLGeOVcj9LQ+s67vBykx4anTjURkbqZslUEUsn2k5xeua2zUk=
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/letsencryptauthorityx2.pem
	letsencryptauthorityx2 = []byte(`-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAJY2TKc4C+SL3JDGzeC33mgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTIwMDMx
WhcNMjAwNjA0MTIwMDMxWjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhJHRCe7eRMdlz/ziq2M5EXLc5
CtxErg29RbmXN2evvVBPX9MQVGv3QdqOY+ZtW8DoQKmMQfzRA4n/YmEJYNYHBXia
kL0aZD5P3M93L4lry2evQU3FjQDAa/6NhNy18pUxqOj2kKBDSpN0XLM+Q2lLiSJH
dFE+mWTDzSQB+YQvKHcXIqfdw2wITGYvN3TFb5OOsEY3FmHRUJjIsA9PWFN8rPba
LZZhUK1D3AqmT561Urmcju9O30azMdwg/GnCoyB1Puw4GzZOZmbS3/VmpJMve6YO
lD5gPUpLHG+6tE0cPJFYbi9NxNpw2+0BOXbASefpNbUUBpDB5ZLiEP1rubSFAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBTF
satOTLHNZDCTfsGEmQWr5gPiJTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AA4eqMjSEJKCF6XRR5pEutkS/e7xgy2vCYYbw1ospQiGQ4FO5TtbvO+5K4v7WR3b
1peMQ03rX0Dr+ylmGNypZahNxTqDiO0X2sHBwJWj/k61+MYq3bRYxKwI6cduTDXb
YQxilGTDNGZUIFKKIloz4zGAl68sj+8pLg534EqKgl8+rWSxclToS1KrydJezokE
dQRXfxu79iscWA3PIj1vbaUBB16lnWJxA3LhTGhUrhZrCnFuOZ93KO8kCKPM7EVo
7c4FCYKI8eWDsf0FF49A4xMUmxPJAPIyZkwQ8KkjpzcTHOmT4CEXUhNu9eMI9qBK
VSFDDMifJ8HzCaVLyMvY1Kf7iR+840EkX1EGC+Z39EaK1hjm314LYpLoYGvYYLJO
/J76XAx8ZgpofqHz1gAEfiMLMLxLQkOjKLXqoUEd5KdnzaO3aLH91gnasy8aD4D5
9RfEO2xcaozD2rbYsoAMVzcZZHw0Smdmobaz2YazMBjFRcqGntg6s5Xqwusaleiy
snjMCC/9mvIPqGyuVnBPTBaUDFDEhX6qD2MX4dzODL91Z0ogYDWcFLN+uLnZKHje
4JoNuzkJ2FXWOREcsW93KXb+3T8COjhTDKvK4H6ufdrZxxusx60ajJAMBzW0XTf5
nm2yGEDtyVoMgJLp0rkiPlormgHxSkFDOJbY94J7yxRK
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem
	letsencryptx2crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAMODTJjAvWslLKN5tm+lKw4wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjM1MDFaFw0yMDEwMTkyMjM1MDFa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOEkdEJ7t5Ex2XP/OKrYzkRctzkK3ESuDb1FuZc3Z6+9UE9f
0xBUa/dB2o5j5m1bwOhAqYxB/NEDif9iYQlg1gcFeJqQvRpkPk/cz3cviWvLZ69B
TcWNAMBr/o2E3LXylTGo6PaQoENKk3Rcsz5DaUuJIkd0UT6ZZMPNJAH5hC8odxci
p93DbAhMZi83dMVvk46wRjcWYdFQmMiwD09YU3ys9totlmFQrUPcCqZPnrVSuZyO
707fRrMx3CD8acKjIHU+7DgbNk5mZtLf9Wakky97pg6UPmA9Skscb7q0TRw8kVhu
L03E2nDb7QE5dsBJ5+k1tRQGkMHlkuIQ/Wu5tIUCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUxbGrTkyxzWQwk37B
hJkFq+YD4iUwDQYJKoZIhvcNAQELBQADggEBAAcSAhaE7rvHxyUnhgkEpMR56o2I
IH+mlw5kknjhAuvaBIAM59MZkFbFg5CrNWt8K+G3UoxJgFwv7HvJJxqwgPpNgXC/
uT3prkvwt+2lvzKJKbqdH+lo40P8EuSyyJOz2hjrRzNMHbJHYDS9OhF5WC5LOQQa
ydgLZ/JHxXgJypEZqcmVgQ+yYBs0XPwXjE7OE8vbx5REwu7gToMIqAoWRoWW2MxS
g28RGPVnHzHk2XV1nZGy9T+NYQ91vWWJr1pzNEFZ0cnA2xGwTeJ+zZ3URCfw3Z1U
+YAL3YUmrvdoRBlASOTmNJmXSo9qvMYPa3DEomAPoFQFZqsSN6kuqDEIqMA=
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/letsencryptauthorityx3.pem
	letsencryptauthorityx3 = []byte(`-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem
	letsencryptx3crosssigned = []byte(`-----BEGIN CERTIFICATE-----
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
	// https://letsencrypt.org/certs/letsencryptauthorityx4.pem
	letsencryptauthorityx4 = []byte(`-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAJObmZ6kjhYNW0JZtD0gE9owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0NDM0
WhcNMjExMDA2MTU0NDM0WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhJHRCe7eRMdlz/ziq2M5EXLc5
CtxErg29RbmXN2evvVBPX9MQVGv3QdqOY+ZtW8DoQKmMQfzRA4n/YmEJYNYHBXia
kL0aZD5P3M93L4lry2evQU3FjQDAa/6NhNy18pUxqOj2kKBDSpN0XLM+Q2lLiSJH
dFE+mWTDzSQB+YQvKHcXIqfdw2wITGYvN3TFb5OOsEY3FmHRUJjIsA9PWFN8rPba
LZZhUK1D3AqmT561Urmcju9O30azMdwg/GnCoyB1Puw4GzZOZmbS3/VmpJMve6YO
lD5gPUpLHG+6tE0cPJFYbi9NxNpw2+0BOXbASefpNbUUBpDB5ZLiEP1rubSFAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBTF
satOTLHNZDCTfsGEmQWr5gPiJTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AF4tI1yGjZgld9lP01+zftU3aSV0un0d2GKUMO7GxvwTLWAKQz/eT+u3J4+GvpD+
BMfopIxkJcDCzMChjjZtZZwJpIY7BatVrO6OkEmaRNITtbZ/hCwNkUnbk3C7EG3O
GJZlo9b2wzA8v9WBsPzHpTvLfOr+dS57LLPZBhp3ArHaLbdk33lIONRPt9sseDEk
mdHnVmGmBRf4+J0Wy67mddOvz5rHH8uzY94raOayf20gzzcmqmot4hPXtDG4Y49M
oFMMT2kcWck3EOTAH6QiGWkGJ7cxMfSL3S0niA6wgFJtfETETOZu8AVDgENgCJ3D
S0bz/dhVKvs3WRkaKuuR/W0nnC2VDdaFj4+CRF8LGtn/8ERaH48TktH5BDyDVcF9
zfJ75Scxcy23jAL2N6w3n/t3nnqoXt9Im4FprDr+mP1g2Z6Lf2YA0jE3kZalgZ6l
NHu4CmvJYoOTSJw9X2qlGl1K+B4U327rG1tRxgjM76pN6lIS02PMECoyKJigpOSB
u4V8+LVaUMezCJH9Qf4EKeZTHddQ1t96zvNd2s9ewSKx/DblXbKsBDzIdHJ+qi6+
F9DIVM5/ICdtDdulOO+dr/BXB+pBZ3uVxjRANvJKKpdxkePyluITSNZHbanWRN07
gMvwBWOL060i4VrL9er1sBQrRjU9iNpZQGTnLVAxQVFu
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem
	letsencryptx4crosssigned = []byte(`-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc6bLEeMfizANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDEwMloXDTIxMDMxNzE2NDEwMlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFg0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4SR0Qnu3kTHZc/84qtjORFy3OQrcRK4NvUW5lzdnr71QT1/T
EFRr90HajmPmbVvA6ECpjEH80QOJ/2JhCWDWBwV4mpC9GmQ+T9zPdy+Ja8tnr0FN
xY0AwGv+jYTctfKVMajo9pCgQ0qTdFyzPkNpS4kiR3RRPplkw80kAfmELyh3FyKn
3cNsCExmLzd0xW+TjrBGNxZh0VCYyLAPT1hTfKz22i2WYVCtQ9wKpk+etVK5nI7v
Tt9GszHcIPxpwqMgdT7sOBs2TmZm0t/1ZqSTL3umDpQ+YD1KSxxvurRNHDyRWG4v
TcTacNvtATl2wEnn6TW1FAaQweWS4hD9a7m0hQIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBTFsatOTLHNZDCTfsGEmQWr5gPiJTANBgkqhkiG9w0BAQsF
AAOCAQEANlaeSdstfAtqFN3jdRZJFjx9X+Ob3PIDlekPYQ1OQ1Uw43rE1FUj7hUw
g2MJKfs9b7M0WoQg7C20nJY/ajsg7pWhUG3J6rlkDTfVY9faeWi0qsPYXE6BpBDr
5BrW/Xv8yT8U2BiEAmNggWq8dmFl82fghmLzHBM8X8NZ3ZwA1fGePA53AP5IoD+0
ArpW8Ik1sSuQBjZ8oQLfN+G8OoY7MNRopyLyQQCNy4aWfE+xYnoVoa5+yr+aPiX0
7YQrY/cKawAn7QB4PyF5//IKSAVs7mAuB68wbMdE3FKfOHfJ24W4z/bIJTrTY8Y5
Sr4AUhtzf8oVDrHZYWRrP4joIcOu/Q==
-----END CERTIFICATE-----`)
	// https://letsencrypt.org/certs/isrg-root-ocsp-x1.pem
	isrgrootocspx1 = []byte(`-----BEGIN CERTIFICATE-----
MIIEtjCCAp6gAwIBAgIRAOkSyQ2QhgQ/FnCA3JZEiqgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwNjA5MTMwNDEx
WhcNMjUwNjEwMTMwNDExWjBUMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
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
AQUEAgUAMA0GCSqGSIb3DQEBCwUAA4ICAQCC1SyXg+js3mvzBv6gHkZBOTP2MPh6
EgQMnWAy2Olu933RBfucYKb4H8JFV7OZQDxa/VJUeVjBwOfQf2Sj7nQp5Aq3m7ug
F228lkLaKOn4c7sX00Px3DpFUpYKHbdGsR69doWRp3mtFuBi3/uAwv1lrvPayzRm
LLtu047CGfD0zmCY/VpuehYZa/g4MLwp6i7Lscvh3B+Jl+daqTYWCNulw8q5gfsE
UXRQzGu5KnBOb6Jw0nrlk7h2YY8N4iP5sBThzl0qRLfy82n4tvs/2IwQd9RBcv6H
+df/sGmjnLvlhAjqjybUQoA/rhkF8PzqKJtpOkaj2qO5XIVJg642T+Kb2qQhohAK
l0YyMxazkQ9qFDuRrljixOIC4iBN40uk5uABF+Vf6UsITJCxkDNakDqKz/nwe+TM
bHXTLuJ1PA+q+Ai73MR9zFW19MffOSaJOR4I/3WeNfUv0nNgYFN8VP60Bjgf7cFc
j+t/zR1pRE/13dguo7FS5EA/52axalq6E+j3/uO7L33+CSBvON0GZlekRcPgvRgq
h0VMhrl6ine7mG0UVBuIg9CLAf+cHCVsDyUiO8x50e5CNEjxh1hxgo46szLU5tHP
aocuXuOLVuLdUat+j/2satKSUStQRigSXAp8fAd5oUXQhSh7GVtIf5eEvGvl04Np
u70vXLDE2hdzTg==
-----END CERTIFICATE-----`)
)
var certificates = [][]byte{isrgrootx1, isrgrootx1crosssigned, isrgrootx2, isrgrootx2crosssigned, letsencryptr3, letsencryptr3crosssigned, letsencrypte1, letsencryptr4, letsencryptr4crosssigned, letsencrypte2, letsencryptauthorityx1, letsencryptx1crosssigned, letsencryptauthorityx2, letsencryptx2crosssigned, letsencryptauthorityx3, letsencryptx3crosssigned, letsencryptauthorityx4, letsencryptx4crosssigned, isrgrootocspx1}

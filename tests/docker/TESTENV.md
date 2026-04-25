# Test Environment — Docker Services

Start all:
```
cd tests/docker && docker compose up -d --build
```

Subnet: `10.99.0.0/24`

## Services

| Service | Protocol | IP | Port | Username | Password | Notes |
|---|---|---|---|---|---|---|
| ssh-alpha | SFTP | 10.99.0.10 | 22 | alpha | alpha123 | Test data in ~/data |
| ssh-beta | SFTP | 10.99.0.11 | 22 | beta | beta123 | Test data in ~/data |
| ssh-gamma | SFTP | 10.99.0.12 | 22 | gamma | gamma123 | Test data in ~/data |
| socks-proxy | SOCKS5 | 10.99.0.20 | 1080 | — | — | Unauthenticated |
| http-proxy | HTTP CONNECT | 10.99.0.21 | 3128 | — | — | Unauthenticated |
| ftp-server | FTP | 10.99.0.30 | 21 | ftpuser | ftp123 | Passive mode, data in ~/data |
| smb-server | SMB | 10.99.0.31 | 445 | smbuser | smb123 | Share: `testshare` |
| webdav-server | WebDAV | 10.99.0.32 | 80 | davuser | dav123 | URL: `http://10.99.0.32` |
| s3-server | S3 (MinIO) | 10.99.0.33 | 9000 | minioadmin | minioadmin123 | Bucket: `testbucket`, Endpoint: `http://10.99.0.33:9000` |
| rsync-server | Rsync | 10.99.0.34 | 873 | rsyncuser | rsync123 | Module: `testmod` |
| nfs-server | NFS | 10.99.0.35 | 2049 | — | — | Export: `/srv/nfs/share`, v3, privileged |
| imap-server | IMAP | 10.99.0.36 | 143 | imapuser | imap123 | Dovecot, no SSL |
| telnet-server | Telnet | 10.99.0.37 | 23 | telnetuser | telnet123 | xinetd + telnetd, data in ~/data |
| iscsi-server | iSCSI | 10.99.0.40 | 3260 | — | — | IQN: `iqn.2024-01.com.axross:test-target`, no auth, 100MB LUN, privileged |
| azurite-server | Azure Blob | 10.99.0.39 | 10000 | devstoreaccount1 | (well-known key) | Blob endpoint: `http://10.99.0.39:10000/devstoreaccount1` |
| azurite-server | Azure Files | 10.99.0.39 | 10000 | devstoreaccount1 | (well-known key) | Same Azurite instance, file share via SDK |
| ftps-server | FTPS | 10.99.0.38 | 21, 990 | ftpsuser | ftps123 | Explicit (STARTTLS :21) + Implicit (:990), passive 21100-21110 |

## Quick Connect Examples (CLI)

```bash
# SFTP
sftp alpha@10.99.0.10       # pw: alpha123

# FTP
ftp 10.99.0.30              # user: ftpuser, pw: ftp123

# SMB
smbclient //10.99.0.31/testshare -U smbuser%smb123

# WebDAV (curl)
curl -u davuser:dav123 http://10.99.0.32/

# S3 (MinIO mc)
mc alias set test http://10.99.0.33:9000 minioadmin minioadmin123

# Rsync
rsync rsync://rsyncuser@10.99.0.34/testmod/

# NFS (mount as root)
mount -t nfs -o vers=3 10.99.0.35:/srv/nfs/share /mnt/nfs

# IMAP (openssl)
openssl s_client -connect 10.99.0.36:143 -starttls imap

# Telnet
telnet 10.99.0.37

# FTPS (explicit, STARTTLS)
curl --ftp-ssl -u ftpsuser:ftps123 -k ftp://10.99.0.38/

# FTPS (implicit, port 990)
curl --ftp-ssl -u ftpsuser:ftps123 -k ftps://10.99.0.38:990/

# iSCSI (open-iscsi)
iscsiadm -m discovery -t sendtargets -p 10.99.0.40:3260
iscsiadm -m node -T iqn.2024-01.com.axross:test-target -p 10.99.0.40:3260 --login

# Azure Blob (az CLI)
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://10.99.0.39:10000/devstoreaccount1;"
az storage container create -n testcontainer
az storage blob upload -c testcontainer -f myfile.txt -n myfile.txt
```

## Axross Profile Config (copy to ~/.config/axross/profiles.json)

```json
{
  "SFTP Alpha": {
    "name": "SFTP Alpha", "protocol": "sftp",
    "host": "10.99.0.10", "port": 22,
    "username": "alpha", "auth_type": "password"
  },
  "FTP Test": {
    "name": "FTP Test", "protocol": "ftp",
    "host": "10.99.0.30", "port": 21,
    "username": "ftpuser", "ftp_passive": true
  },
  "SMB Test": {
    "name": "SMB Test", "protocol": "smb",
    "host": "10.99.0.31", "port": 445,
    "username": "smbuser", "smb_share": "testshare"
  },
  "WebDAV Test": {
    "name": "WebDAV Test", "protocol": "webdav",
    "host": "10.99.0.32", "port": 80,
    "username": "davuser", "webdav_url": "http://10.99.0.32"
  },
  "S3 MinIO": {
    "name": "S3 MinIO", "protocol": "s3",
    "host": "10.99.0.33", "port": 9000,
    "username": "minioadmin",
    "s3_bucket": "testbucket", "s3_endpoint": "http://10.99.0.33:9000"
  },
  "Rsync Test": {
    "name": "Rsync Test", "protocol": "rsync",
    "host": "10.99.0.34", "port": 873,
    "username": "rsyncuser", "rsync_module": "testmod"
  },
  "NFS Test": {
    "name": "NFS Test", "protocol": "nfs",
    "host": "10.99.0.35", "port": 2049,
    "nfs_export": "/srv/nfs/share", "nfs_version": 3
  },
  "IMAP Test": {
    "name": "IMAP Test", "protocol": "imap",
    "host": "10.99.0.36", "port": 143,
    "username": "imapuser", "imap_ssl": false
  },
  "Telnet Test": {
    "name": "Telnet Test", "protocol": "telnet",
    "host": "10.99.0.37", "port": 23,
    "username": "telnetuser"
  },
  "FTPS Test": {
    "name": "FTPS Test", "protocol": "ftps",
    "host": "10.99.0.38", "port": 21,
    "username": "ftpsuser", "ftp_passive": true
  },
  "iSCSI Test": {
    "name": "iSCSI Test", "protocol": "iscsi",
    "host": "10.99.0.40", "port": 3260,
    "iscsi_iqn": "iqn.2024-01.com.axross:test-target"
  },
  "Azure Blob Test": {
    "name": "Azure Blob Test", "protocol": "azure_blob",
    "host": "10.99.0.39", "port": 10000,
    "username": "devstoreaccount1",
    "azure_connection_string": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://10.99.0.39:10000/devstoreaccount1;",
    "azure_container": "testcontainer"
  },
  "Azure Files Test": {
    "name": "Azure Files Test", "protocol": "azure_files",
    "host": "10.99.0.39", "port": 10000,
    "username": "devstoreaccount1",
    "azure_connection_string": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://10.99.0.39:10000/devstoreaccount1;",
    "azure_share": "testshare"
  }
}
```

## Not Yet in Docker (supported protocols without test containers)

| Protocol | Reason | What's needed |
|---|---|---|
| OneDrive | OAuth, cloud | Not practical in Docker |
| SharePoint | OAuth, cloud | Not practical in Docker |
| Google Drive | OAuth, cloud | Not practical in Docker |
| Dropbox | OAuth, cloud | Not practical in Docker |

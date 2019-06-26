# Forencis

```
    * file          (file)
    * Exiftool      (exiftool file)
    * Binwalk       (binwalk -e file) [usage : binwalk —dd “.*”] file
    * jstego-0.3    (extracts any hidden file)
    * color         ()
    * filecarve     (dd command)
    * wireshark       (don’t say u don’t know this)
    * hexdump
    * zipdetails -v & zipinfo (for info on zip)
    * mount -t iso9660 challengefile /mnt/challenge
    * difference btw 2 file can be seen as =>   
        xxd file1.jpg > a.hex
        xxd file2.jpg > a1.hex
        diff a.hex a1.hex
    * 7z to extract 7z files
    * Audacity 
    * debugfs     (tell file headers and if they are wrong or right)
    * foremost    (file carving)
    * image 
    * volatility  (memory dump analysis)
    * zsteg       (zsteg --all file.extension)
   split gif image to its frame
   remove white/black or any background from image
   combine images
   stegsolve
   LSB
   steghide if you get a password from somewhere 
        ==========  [ imagemagick ] DOES IT ALL ==========



```

# Linux

## List All Mounted Drives 

```
lsblk

NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda      8:0    0    64G  0 disk 
sda1   8:1      0    64G  0 part /etc/hosts
sdb             0    128G 0
sdb1            0    128G 0
sdb2            0    16G  0
```
so there are 2 disks attached, sda and sdb <br/>
sda only 1 main partition and sda2 has 2 partition

## Vieweing all partition and there offsets 

```
$ fdisk -u -l /dev/sdb

Disk /dev/sda: 64 GiB, 68719476736 bytes, 134217728 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xd9b2afbf

Device     Boot Start       End        Sectors    Size  Id Type
/dev/sdb1  *     2048      134217727   134215680  128G  83 Linux
/dev/sdb2  *     134217727 134215680      215110  16G   83 Linux

```
so it have 2 partition from<br/>
parition 1 of 128GB is from offset `2048*sectorSize` to `134217727*sectorSize`<br/>
parition 2 of 16GB is from offset `134217727*sectorSize` to whtever<br/>
where sectorSize=512


## creating new partition

```
$ sudo fdisk  /dev/sda
```

OPTIONS :
* w : write new partition
* p : list all partition


## creating File system inside new created partition

```
mkfs.ext4 /dev/sda1
```


## Mounting sdb second partition manually 

suppose i need to mount sdb2 to my /test directory
```
$ echo $((134217727*512))  # caluculate offset
< 68719476224
$ sudo mount -o loop,offset=68719476224 /dev/sdb /test
```
and mounted


# Mac Mounts basics


## List All Mounted Drives and their Partitions from the Terminal(lsblk in linux)

```
$ diskutil list

/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *121.3 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:          Apple_CoreStorage Macintosh HD            120.5 GB   disk0s2
   3:                 Apple_Boot Recovery HD             650.0 MB   disk0s3

/dev/disk1 (internal, virtual):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:                  Apple_HFS Macintosh HD           +120.1 GB   disk1

```
so i can just read these images or partion like

`dd if=/dev/disk0s3 of=~/Desktop/asdf bs=1m skip=10000 count=40668937`


## fixing corrupted Partitions

> suppose we got a corrupted image in SD card and we need to fix it, so lets plug it in, and follow me:

* diskutil list
```
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *121.3 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:          Apple_CoreStorage Macintosh HD            120.5 GB   disk0s2
   3:                 Apple_Boot Recovery HD             650.0 MB   disk0s3

/dev/disk1 (internal, virtual):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:                  Apple_HFS Macintosh HD           +120.1 GB   disk1
                                 Logical Volume on disk0s2
                                 125AEBF4-ECC4-4976-9746-B3136C9D8A22
                                 Unencrypted

/dev/disk3 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:     FDisk_partition_scheme                         *1.0 TB      disk3
   1:             Windows_FAT_32 ELEMENTS                970.0 GB     disk3s1
   1:             BootSector			                     30.0 GB      disk3s2

```


* diskutil info disk3

> so assume /dev/disk3s2 is corrupted, 

* `dd if=/dev/disk3s2 out=~/Desktop/asdf bs=1m`

> now try foremost,Binwalk, try manual mounting `mount -t iso9660 ~/Desktop/asdf /whtever`,debugfs to try finding bug, check magic number










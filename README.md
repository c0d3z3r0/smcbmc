# Supermicro BMC firmware image decryptor

This tiny tool can decrypt Supermicro BMC firmware images by first reading the
keys from `libipmi.so` inside the rootfs, then decrypting the headers of the
three regions rootfs, webfs and metadata.



## Questions & Answers

### How to use it?

Just provide the encrypted image as input and a filename for the decrypted
image:

~~~sh
./smcbmc.py SMT_X11_xyz.bin decrypted.bin
~~~

### How is that possible? The image is encrypted!

This is a very nice example of Security-by-Obscurity ...

They keys are hardcoded in `libipmi.so`, which contains the code to decrypt and
flash the image through the web interface or via IPMI. This library is inside
the root filesystems, a CRAMFS. The header of this filesystem was encrypted with
AES-CBC using these keys, to "protect" the firmware image. That means, the main
part of the filesystem is unencrypted and can be extracted to get the keys.

### Can I modify the decrypted filesystem(s)?

Yep. Just split the image with `dd` or the tool of your choice. Look at offset
`0x01fc0000` for the metadata section containing the other offsets.

### Can I flash the encrypted image?

Yes, the BMC accepts unencrypted images, too.

### Can I flash a modified image?

Yes, you just have to adapt the offsets, sizes and CRC checksums in the
metadata section. Use [ipmi_firmware_tools](https://github.com/devicenull/ipmi_firmware_tools)
for example.

### I have been hacked and they used your tool!

Well, this is not a question. You should contact someone helping you to fix your
(physical) security issues. This is not a "hacking tool" ...

### You published our encryption keys / secret information / our intellectual property!!!

No, I did not. You published the keys in the image.

### You are infringing our Copyright!!!11111

Uhm, nope.

## More information

* [Eclypsium Blog: INSECURE FIRMWARE UPDATES IN SERVER MANAGEMENT SYSTEMS](https://eclypsium.com/2018/09/06/insecure-firmware-updates-in-server-management-systems/)
* [RAPID7 Blog: Supermicro IPMI Firmware Vulnerabilities](https://blog.rapid7.com/2013/11/06/supermicro-ipmi-firmware-vulnerabilities/)
* [Supermicro: Cryptographic Signed BMC Firmware](https://www.supermicro.com/en/support/security_Cryptographic)
* [ipmi_firmware_tools](https://github.com/devicenull/ipmi_firmware_tools)

## License

Copyright (C) 2020 Michael Niewöhner

This is open source software, licensed under GPLv2. Refer to the license header
in each covered file. See [LICENSE](LICENSE) for the full license.

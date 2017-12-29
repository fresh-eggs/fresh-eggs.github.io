## Summary
### edit: This vulnerability has been assigned CVE-2017-17763.

SuperBeam is an excellent file transfer application which enables users from iOS, Android and even a PC to seamlessly transfer files through WiFi direct, over a local LAN or via NFC.

With over 10 PB of file transfers since its creation and well over 10 million downloads, it is certainly a mainstay in the file transfer market.

Playing around with it recently, we were able to spot a few flaws within the file transfer process. Given a properly placed attacker, the possibility to arbitrarily inject data into any given transfer is alive and well! 

<br><br>
## Affected Products

Versions of SuperBeam / WiFi Direct Share <= 4.1.3

<br><br>
## Impact

During the file transfer process, SuperBeam will offer up the file to be transferred via an HTTP server hosted on the sending device. Any properly positioned attacker is able to arbitrarily inject anything from a text file to an APK onto the receivers' device through a MiTM attack.

This is accomplished by having the attacker spoof the sending device via ARP Poisoning, while simultaneously running an instance of SuperBeam, whether as an app or the PC version.

The most significant impact appears to be in the context of users making use of SuperBeam to transfer apps. In this type of transfer, a user is inclined to install and run whatever they receive, making this a perfect scenario for the attacker to inject a malicious APK.

<br><br>
## Technical Details / Proof of Concept

### Over the LAN

The majority of the research was performed using devices on the same LAN, although via WiFi direct, the results are no different, i.e., sender starts an HTTP server on a LAN and waits for GET requests, no data validation.

Below we will walk through an APK injection scenario / POC. This could just as easily have been a scenario where two parties are exchanging public keys and the attackers injects their own.

Here we see a user initiate a file transfer by selecting an app to send via SuperBeam:
![user selecting the file they would like to transfer.]({{site.url}}/images/figure-0.png)
<br><br>

SuperBeam is now active and has set up a server that will provide the flashlight app APK:
![super beam HTTP server running.]({{site.url}}/images/figure-1.png)
<br><br>

Here we see that the attacker has poisoned the receivers ARP cache, pretending to be the sender at 192.168.2.27:
![dat arp.]({{site.url}}/images/figure-2.png)
<br><br>

The attacker can then run an instance of SuperBeam on a mobile device or a PC and offer up the content they intend to inject into the transfer:
![PC stands for personal computer.]({{site.url}}/images/figure-3.png)
<br><br>

**NOTE**: Only the pro version enables downloads to mobile from PC, **inadvertently increasing the attack surface for paying customers only.** Otherwise, the receiver is met with the following:
![]({{site.url}}/images/figure-4.png)
<br><br>

Next, the receiver will simply scan the QR code provided by the sender, this will issue the following requests:
![]({{site.url}}/images/figure-5.png)
<br><br>

Since we are injecting our malicious APK via the PC version of SuperBeam, we don't offer up a jsonlist, hence the 404.

Below are the contents of the jsonlist offered up by the sending device:
![sweet, sweet metadata.]({{site.url}}/images/figure-6.png)
<br><br>

Had this scenario been weaponized, **the attacker could have used the information provided by the jsonlist from the original sender to mirror the application being transferred**, leaving the receiver suspecting nothing.

On the attacker side at this point, we see the request come into our SuperBeam instance instead of the true sender's instance:
![dat arp.]({{site.url}}/images/figure-7.png)
<br><br>

The receiver will be none the wiser as there are **zero data integrity checks performed on the content received**:
![what is a keyed HMAC?]({{site.url}}/images/figure-8.png)
<br><br>

Finally, the user simply steps through the installation process and the device is now fully compromised:
![we did it guys!]({{site.url}}/images/figure-9.png)
<br><br>

<br><br>
## Over WiFi Direct

Due to the nature of the implementation of the WiFi Direct file transfer feature in SuperBeam, the attack described above will have no trouble functioning in a WiFi Direct scenario.

Although some extra effort will be required on the part of the attacker in order to gain access to the LAN created by SuperBeam.

SuperBeam performs a WiFi Direct transfer with the help of a temporary wireless access point, hosted by the device sending files:
![]({{site.url}}/images/figure-10.png)
<br><br>

After experimenting with how the application sets up this temporary network, a few flaws were uncovered that make it possible for an attacker to break into the network.

* **Static SSID**: As seen in the figure above, the SSID for SuperBeam WiFi direct transfers all follow a similar structure. (Ex: "DIRECT-Yf-S", DIRECT-<two random characters>-S). Once set, it looks to persist even after deleting the app and reinstalling it.


* **Static WPA2 Key**: The temporary network makes use of an 8 character password composed of lower and upper case letters, as well as numbers (no special characters observed during the period of this audit).

An attacker could capture a handshake between client and server, collect a hash of the key and perform an offline hash cracking attack on the 8 character password.

Since it is the case that the password appears to be static for all transfers initiated by a given sender, once cracked, the attacker has the ability to MiTM every instance of a WiFi Direct transfer offered by the sender in question.

<br><br>
## Recommended Mitigation

The vulnerabilities in the current version of SuperBeam boil down to the lack of any form of data validation.

In order to patch up SuperBeam, the following modifications are recommended:

<br><br>
### HTTPS

Offer up all file transfers via HTTPS in order to help make arbitrary MiTM attacks on the file transfer process less trivial.

<br><br>
### Data validation

Using a shared secret between the sender and receiver, the files transferred could have HMACs calculated on them.

Even if the attacker could inject their own file into the transfer, without knowledge of the shared secret, the attacker should not be able to calculate a valid HMAC for their injected file.

At the very least, this would provide SuperBeam a way to validate that the data being transferred was not tampered with.

<br><br>
### Beef up WiFi Direct

It would be highly advisable to simply randomize the SSID used by the wifi direct transfer every time a new SuperBeam server starts up.

Not only the SSID but the network key should also change every transfer. If it were randomized, even with a weak 8 character key, the cracked key would only be useful to the attacker for a single wifi direct transfer.

This would render efforts to crack it offline for future use completely futile, as the window of opportunity is reduced to a single transfer.

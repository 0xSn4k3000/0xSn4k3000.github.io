---
title: HTB - Inside Scoop from Defcon-x-IOT-Village:-House-Edge-CTF writeup
date: 2023-08-26 02:05:00 +0200
categories: [Hardware & IoT]
tags: [upnp,burpsuite,wireshark]
author: 1
img_path: /assets/posts_imgs/2023-08-26-HTB-InsideScoop/
---

Hello friends , in this post i will solve `Inside Scoop` challenge from IoTVillage and hackthebox , its an easy hardware challenge, so lets do it

so starting with the challenge description.
>Before we start our mission, we need to be sure that we won't raise any alarms. Our inside informant has given us knowledge of an API that is used by the security system installed in the facility. The state-of-the-art security surveillance system uses whitelist-based face recognition, so we won’t be able to pass through. We’ll need to access the interface and stop the feed! 

so from this description we can understand that there is a [`CCTV`](https://en.wikipedia.org/wiki/Closed-circuit_television) system that we need to stop.

## Hints

first things first , if you are someone who like to solve things on your own like me , but you are stuck then here some hints that can help. ^_^


## Solution

Starting with downloading the necessary files to play the challenge , unzip it and we got two files.
a [`pcap`](https://en.wikipedia.org/wiki/Pcap) file and an image , so by opening the image that called `network_layout.png` we can get a hint of what we will work with.

![network leyout](network_layout.png)
_network layout_

so from this layout you can imagine the look of the network , the Camera System is inside the LAN with a router in the edge of the local network connecting to Internet. good lets open the pcap file and see what's inside.


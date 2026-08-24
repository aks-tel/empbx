<p>
    The idea to have such software on the hand, has been in my mind for a long time. <br>
	Started developing projects such as: tSIP, HATS, I realized that I don't have a solution that I could be used as a base for the new ones and able to provide the basic VoIP functionality. <br>
	Freeswitch was not suitable in this case, since it should to be small, portable and ready for embedding as possible. <br>
	Baresip (as-is, witch I usually used), didn't suit in this time. <br>
	So I decided it's time to write something that would satisfy these needs. <br> 
</p>

Requirements for the first version: <br>
<ul>
 <li><strong>Small, portable and configurable</strong>
	<p>
    	It should be able to work on devices with 512Mb RAM (such as: OrangePI One or MTK SoCs MT7621, as possible) <br>
        Capable with: OpenWRT and FreeBSD <br>
    </p>
 </li>
 <li><strong>Supports protocols:</strong>
  <p>
     - SIP (must be) <br>
     - WebRTC (optional) <br>
   </p>
  </li>
 <li><strong>Telephony capabilities:</strong>
  <p>
    - SIP registrar / locations (for local users) <br>
    - External SIP gateways (for connecting FXO/FXS equipments) <br>
    - Supports audio and video (as possible) calls <br>
    - Calls routing, something similar to FreeSWITCH dialplan but simpler.
  </p>
 </li>
 <li><strong>Management capabilities:</strong>
  <p>
    - Web based management interface (optional) <br>
    - JSON-RPC services for automation and integration purposes
    </p>
 </li>
</ul>

	
### v0.0.1
 This is an experimental version, for testing purposes only. <br>
 Actually, it's a b2bua client with extra features. <br>
 Based on libre and baresip and implemented following functions: <br> 
  - SIP registrar and location server <br>
  - SIP gateways <br>  
  - Inbound/Outbound/Intrecom calls routing <br>
  - Simple dialplan with applications <br>
  - Codecs: G711 <br>
  - Local users db

### Build and run
 Just perform script: build.sh, and wait a bit. <br>
 Default home path: /opt/empbx <br>
 If everything compiles without errors you can go there and try to start it: ./bin/empbxd -a debug <br>
 There is a single config file: /opt/empbx/configs/empbxd-conf.xml, you can describe users, gateways, dialplan and etc, there. <br>
 




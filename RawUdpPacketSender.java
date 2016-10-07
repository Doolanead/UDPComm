import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.*;
import java.net.*;

public class RawUdpPacketSender {
    private static Logger logger = Logger.getLogger(RawUdpPacketSender.class.getName());

    private Pcap pcap = null;
    private int headerLength = getHeaderLength();
    private int UDP_SOURCE_PORT = 7006;
    private byte[] sourceMacAddress;
    private byte[] destinationMacAddress;
    private static String interfaz = "h1-eth0";
    private String IPdst = null;
    
    public static String getMAC(String ip, String mascara ) {
		String nmap = "nmap -sn " + ip + "/" + mascara;
		String arp = "arp -a ";
		Process p1,p2;

		try {
			System.out.println(nmap + "\n" + arp + "\n" + interfaz ); 
			//p1 = Runtime.getRuntime().exec(nmap);
			//p1.waitFor();
			p2 = Runtime.getRuntime().exec(arp); 
			p2.waitFor();
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(p2.getInputStream()));

			String line = "";
			while ((line = reader.readLine()) != null) {
				if( line.contains("("+ip+")") ){
					String[] datos = line.split(" ");
					for (int i = 0; i < datos.length; i++){
						if ( datos[i].split(":").length == 6 ){					
							return datos[i];
						}
					}
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
    
    public static boolean validIP (String ip) {
        try {
            if ( ip == null || ip.isEmpty() ) {
                return false;
            }

            String[] parts = ip.split( "\\." );
            if ( parts.length != 4 ) {
                return false;
            }

            for ( String s : parts ) {
                int i = Integer.parseInt( s );
                if ( (i < 0) || (i > 255) ) {
                    return false;
                }
            }
            if ( ip.endsWith(".") ) {
                return false;
            }

            return true;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }
    
    public void setIPdst( String ip ){
    	String macAddress;
    	if ( validIP(ip) ){
    		if ( ( macAddress = getMAC(ip, "24")) == null )
    			macAddress = System.getProperty("gateway_mac_address", "");
    		destinationMacAddress = hexStringToByteArray(macAddress.replaceAll(":", ""));
    		System.out.println(macAddress);
    	}
    	else
    		System.exit(-1);;
    }
    
    public RawUdpPacketSender() {
        try {
            pcap = createPcap();
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to start pcap library.", e);
        }
    }

    public void sendPacket(URI destination, byte[] packet)
            throws IOException {
        int port = destination.getPort();
        InetAddress address = InetAddress.getByName(destination.getHost());
        byte[] destinationAddress = address.getAddress();
        sendPacket(destinationAddress, port, packet);
    }

    private Pcap createPcap() throws IOException {
        PcapIf device = getPcapDevice();
        if (device == null) {
            return null;
        } 
        sourceMacAddress = device.getHardwareAddress();  //Use device's MAC address as the source address
        StringBuilder errorBuffer = new StringBuilder();
        int snapLen = 64 * 1024;
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snapLen, flags, timeout,
                errorBuffer);
        if (logger.isLoggable(Level.INFO)) {
            logger.info(String.format("Pcap starts for device %s successfully.", device.getName()));
        }
        return pcap;
    }
    
    private PcapIf getPcapDevice() {
        List<PcapIf> allDevs = new ArrayList<PcapIf>();
        StringBuilder errorBuffer = new StringBuilder();
        int r = Pcap.findAllDevs(allDevs, errorBuffer);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            logger.log(Level.SEVERE, String.format("Can't read list of devices, error is %s",
                    errorBuffer.toString()));
            return null;
        }
        String deviceName = System.getProperty("raw_packet_network_interface", interfaz);
        
//        for (int i = 0; i < allDevs.size(); i++){
//        	logger.info(i + " " + allDevs.get(i));
//        }
//        
        for (PcapIf device : allDevs) {
            if (deviceName.equals(device.getName())) {
                return device;
            }
        }
        return allDevs.get(0);
    }

    private int getHeaderLength() {
        return 14 + 20 + 8; //Ethernet header + IP v4 header + UDP header
    }

    private void sendPacket(byte[] destinationAddress, int port, byte[] data)
            throws IOException {
        int dataLength = data.length;
        int packetSize = headerLength + dataLength;
        JPacket packet = new JMemoryPacket(packetSize);
        packet.order(ByteOrder.BIG_ENDIAN);
        packet.setUShort(12, 0x0800);
        packet.scan(JProtocol.ETHERNET_ID);
        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.source(sourceMacAddress);
        ethernet.destination(destinationMacAddress);
        ethernet.checksum(ethernet.calculateChecksum());

        //IP v4 packet
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4.Ip4Type.UDP);
        ip4.length(packetSize - ethernet.size());
	System.out.println(InetAddress.getLocalHost().getHostAddress());
        byte[] sourceAddress = getLocalIP();
        ip4.source(sourceAddress);
        ip4.destination(destinationAddress);
        ip4.ttl(32);
        ip4.flags(0);
        ip4.offset(0);
        ip4.checksum(ip4.calculateChecksum());

        //UDP packet
        packet.scan(JProtocol.ETHERNET_ID);
        Udp udp = packet.getHeader(new Udp());
        udp.source(UDP_SOURCE_PORT);
        udp.destination(port);
        udp.length(packetSize - ethernet.size() - ip4.size());
        udp.checksum(udp.calculateChecksum());
        packet.setByteArray(headerLength, data);
        packet.scan(Ethernet.ID);

        if (pcap.sendPacket(packet) != Pcap.OK) {
            throw new IOException(String.format(
                    "Failed to send UDP packet with error: %s", pcap.getErr()));
        }
    }

private byte[] getLocalIP(){

	byte[] a;
	String ip;
    try {
	a = InetAddress.getLocalHost().getAddress();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            // filters out 127.0.0.1 and inactive interfaces
            if (iface.isLoopback() || !iface.isUp())
                continue;

            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while(addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                ip = addr.getHostAddress();
                if( iface.getDisplayName().equals(interfaz) && !ip.equals(InetAddress.getLoopbackAddress()) ){
	a = addr.getAddress();
	System.out.println(a);
            }
        }}
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
	return a;
}


    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
                    .digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) throws IOException {
        RawUdpPacketSender sender = new RawUdpPacketSender();
        byte[] packet = "Hello".getBytes();
        sender.setIPdst("10.0.0.2");
        URI destination = URI.create("udp://10.0.0.2:9876");
        sender.sendPacket(destination, packet);
    }
}

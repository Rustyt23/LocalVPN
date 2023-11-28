package com.example.localvpn;


import android.util.Log;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.Address;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.ZoneTransferException;
import org.xbill.DNS.dnssec.ValidatingResolver;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DnsChange {
    static String TAG = DnsChange.class.getSimpleName();

    public static String extractIpAddress(String dnsResponse) {
        Pattern ipPattern = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

        Matcher matcher = ipPattern.matcher(dnsResponse);
        String ipAddress = null;
        while (matcher.find()) {
            ipAddress = matcher.group();
        }

        return ipAddress;
    }
    public static String DOHresolver(String name) {

        DohResolver resolver = new DohResolver("https://doh.accelerint.net/dns-query");
        int type1 = org.xbill.DNS.Type.A;
        int dclass = DClass.IN;
        Record rec = Record.newRecord(Name.fromConstantString(name), type1, dclass);
        org.xbill.DNS.Message query = org.xbill.DNS.Message.newQuery(rec);
        org.xbill.DNS.Message response;
        try {
            response = resolver.send(query);
            String ips = response.sectionToString(1);
            String ip=extractIpAddress(ips);
            Log.w(TAG,"IP extracted from response: "+ip);
            return ip;
        } catch (IOException e) {
            e.printStackTrace();
            return "empty";// Log the exception for debugging
        }

    }

    public static ByteBuffer handle_dns_packet(Packet packet) {
        try {
            ByteBuffer packet_buffer = packet.backingBuffer;
            packet_buffer.mark();
            byte[] tmp_bytes = new byte[packet_buffer.remaining()];
            packet_buffer.get(tmp_bytes);
            packet_buffer.reset();
            Message message = new Message(tmp_bytes);
            Record question = message.getQuestion();
            ConcurrentHashMap<String, String> DOMAINS_IP_MAPS = new ConcurrentHashMap<>();
            int type = question.getType();
            Name query_domain = message.getQuestion().getName();
            String query_string = query_domain.toString();
            if (type == 1) {
//                if (query_string.equals("doh.accelerint.net.")) {
//                    Log.d(TAG, "doh.accelerint.net resolving: " + question.getType() + " :" + query_string);
//                    return null;
//                }

                Log.d(TAG, "Resolving: " + question.getType() + " :" + query_string);
                String ip;
                if(query_string.equals("doh.accelerint.net."))
                    ip="108.137.61.99";
                else
                    ip = DOHresolver(query_string);
                DOMAINS_IP_MAPS.put(query_string, ip);
                if (ip.equals("empty")) {
                    Log.w(TAG, "LocalDNS is used for "+query_string);

                    return null;
                }

                Log.d(TAG, "query2: " + question.getType() + " :" + query_string + " and answer: " + ip);
                InetAddress address = Address.getByAddress(DOMAINS_IP_MAPS.get(query_string));
                Record record;
                record = new ARecord(query_domain, 1, 86400, address);
                message.addRecord(record, 1);
                message.getHeader().setFlag(Flags.QR);
                packet_buffer.limit(packet_buffer.capacity());
                packet_buffer.put(message.toWire());
                packet_buffer.limit(packet_buffer.position());
                packet_buffer.reset();
                packet.swapSourceAndDestination();
                packet.updateUDPBuffer(packet_buffer, packet_buffer.remaining());
                packet_buffer.position(packet_buffer.limit());
                Log.d(TAG, "hit: " + question.getType() + " :" + query_domain + ": " + address.getHostName());
                return packet_buffer;
            } else return packet_buffer;
        } catch (Exception e) {
            e.printStackTrace();
            Log.d(TAG, "dns hook error", e);
            return null;
        }

    }

}

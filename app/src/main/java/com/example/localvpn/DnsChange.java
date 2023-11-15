package com.example.localvpn;



import android.util.Log;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.Address;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;

public class DnsChange {

    static String TAG = DnsChange.class.getSimpleName();


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
            if(type==1)
            {DOMAINS_IP_MAPS.put("fast.com.","3.110.192.63");
            DOMAINS_IP_MAPS.put("fiber.google.com.","3.110.192.63");
            DOMAINS_IP_MAPS.put("speedtest.net.","3.110.192.63");
            DOMAINS_IP_MAPS.put("www.speedtest.net.","3.110.192.63");
            Name query_domain = message.getQuestion().getName();
            String query_string = query_domain.toString();
            Log.d(TAG, "query: " + question.getType() + " :" + query_string);
            if (!DOMAINS_IP_MAPS.containsKey(query_string)) {
                query_string = "." + query_string;
                int j = 0;
                while (true) {
                    int i = query_string.indexOf(".", j);
                    if (i == -1) {
                        return null;
                    }
                    String str = query_string.substring(i);

                    if (".".equals(str) || "".equals(str)) {
                        return null;
                    }
                    if (DOMAINS_IP_MAPS.containsKey(str)) {
                        query_string = str;
                        break;
                    }
                    j = i + 1;
                }
            }
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
            Log.d(TAG, "hit: " + question.getType() + " :" + query_domain + " :" + address.getHostName());
            return packet_buffer;}
            else return packet_buffer;
        } catch (Exception e) {
            Log.d(TAG, "dns hook error", e);
            return null;
        }

    }

}

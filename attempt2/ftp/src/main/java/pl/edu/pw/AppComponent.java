/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pl.edu.pw;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * Application for FTP load balancig.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService; // TODO check or delete

    private static final String APPLICATION_NAME = "pl.edu.pw";
    private static final PacketPriority PACKET_INTERCEPT_PRIORITY = PacketPriority.MEDIUM;
    private static final List<Integer> STANDARD_FTP_PORTS = Arrays.asList(20, 21);
    private static final int FLOW_PRIORITY = PACKET_INTERCEPT_PRIORITY.priorityValue() + 5;
    private static final int FLOW_TIMEOUT_IN_SEC = 20;

    /**
     * Shared IP address
     */
    private Ip4Address sharedAddress;
    /**
     * FTP servers assigned to shared IP address
     */
    private List<Ip4Address> serversAssignedToSharedAddress = new ArrayList<>();
    /**
     * Host IP to shared address redirect IP mapping
     */
    private Map<Ip4Address, Ip4Address> sharedAddressRedirectForHosts = new HashMap<>();
    /**
     * FTP session to changed IP address mapping
     */
    private Map<FtpSessionKey, Ip4Address> activeFtpSessions = new HashMap<>();

    private FtpPacketProcessor ftpPacketProcessor = new FtpPacketProcessor();
    private Random random = new Random();
    private ApplicationId appId;
    private TrafficSelector arpSelector;
    private TrafficSelector ipv4Selector;

    @AllArgsConstructor
    @Getter
    @EqualsAndHashCode
    @ToString
    private class FtpSessionKey {
        private PortNumber srcPort;
        private Ip4Address srcIp;
        private Ip4Address dstIp;
    }

    private void setSharedAddress(Ip4Address newSharedAddress) {
        sharedAddress = newSharedAddress;
    }

    // TODO delete
    private static final Ip4Address TEST_SHARED_ADDRESS = Ip4Address.valueOf("10.0.1.20");
    private static final Ip4Address TEST_SERVER_1 = Ip4Address.valueOf("10.0.1.1");
    private static final Ip4Address TEST_SERVER_2 = Ip4Address.valueOf("10.0.1.2");
    private static final Ip4Address TEST_SERVER_3 = Ip4Address.valueOf("10.0.1.3");

    // TODO load from REST and check for correctness
    private void setupTestConfig() {
        setSharedAddress(TEST_SHARED_ADDRESS);
        serversAssignedToSharedAddress.add(TEST_SERVER_1);
        // serversAssignedToSharedAddress.add(TEST_SERVER_2);
        // serversAssignedToSharedAddress.add(TEST_SERVER_3);
    }

    // TODO delete
    private void clearTestConfig() {
        setSharedAddress(null);
        serversAssignedToSharedAddress.clear();
        sharedAddressRedirectForHosts.clear();
        activeFtpSessions.clear();
    }

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APPLICATION_NAME);
        // Priority must be higher (lower in number) than the FWD app (which is "director(2)")
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(1));
        setupTestConfig(); // TODO delete
        requestIntercepts();
        log.info("Started: " + appId.name());
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(ftpPacketProcessor);
        ftpPacketProcessor = null;
        withdrawIntercepts();
        // TODO drop all flows installed by this app
        clearTestConfig();
        log.info("Stopped: " + appId.name());
    }

    // This is not necessary when ProxyARP and FWD apps are activated
    private void requestIntercepts() {
        arpSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build();

        ipv4Selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(Ip4Prefix.valueOf(sharedAddress, Ip4Prefix.MAX_MASK_LENGTH))
                .build();

        packetService.requestPackets(arpSelector, PACKET_INTERCEPT_PRIORITY, appId);
        packetService.requestPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
    }

    private void withdrawIntercepts() {
        packetService.cancelPackets(arpSelector, PACKET_INTERCEPT_PRIORITY, appId);
        packetService.cancelPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
    }

    private Optional<Ip4Address> selectNextServerIpAddress(Ip4Address srcIp) {
        log.info("Select next server IP. Current host-server mapping: {}", sharedAddressRedirectForHosts);
        if (sharedAddressRedirectForHosts.containsKey(srcIp)) {
            log.info("Cached IP for host: {} is: {}", srcIp, sharedAddressRedirectForHosts.get(srcIp));
            return Optional.of(sharedAddressRedirectForHosts.get(srcIp));
        } else {
            int index = random.nextInt(serversAssignedToSharedAddress.size());
            Ip4Address redirectIp = serversAssignedToSharedAddress.get(index);
            sharedAddressRedirectForHosts.put(srcIp, redirectIp);
            log.info("Selecting new value and putting into map. Key: {} value: {}", srcIp, redirectIp);
            return Optional.ofNullable(redirectIp);
        }
    }

    private void installRuleAndForward(PacketContext context, PortNumber outPort) {
        log.info("Installing rule");
        Ethernet inPkt = context.inPacket().parsed();
        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC())
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(srcIpPrefix)
                .matchIPDst(dstIpPrefix)
                .matchIPProtocol(ipv4Packet.getProtocol())
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(outPort)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(FLOW_PRIORITY)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), outPort);
        context.treatmentBuilder().setOutput(outPort);
        context.send();
        context.block();
    }

    private void installRuleAndForward(PacketContext context, PortNumber outPort, Ip4Address newDstIp) {
        log.info("Installing rule with destination IP modification");
        Ethernet inPkt = context.inPacket().parsed();
        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC())
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(srcIpPrefix)
                .matchIPDst(dstIpPrefix)
                .matchIPProtocol(ipv4Packet.getProtocol())
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setIpDst(newDstIp)
                .setOutput(outPort)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(FLOW_PRIORITY)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), outPort);
        ipv4Packet.setDestinationAddress(newDstIp.toInt());

        ipv4Packet.resetChecksum();
        inPkt.setPayload(ipv4Packet);
        inPkt.resetChecksum();
        packetService.emit(new DefaultOutboundPacket(
                context.inPacket().receivedFrom().deviceId(),
                treatment,
                ByteBuffer.wrap(inPkt.serialize())));
        // context.block();
        // context.treatmentBuilder().setIpDst(newDstIp).setOutput(outPort);
        // context.send();
        context.block();
    }

    private void installSymmetricalRuleChangeSrcIpAndForward(PacketContext context, PortNumber outPort, Ip4Address newSrcIp) {
        log.info("Installing rule with src IP modification");
        Ethernet inPkt = context.inPacket().parsed();
        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(outPort)
                .matchEthSrc(inPkt.getDestinationMAC())
                .matchEthDst(inPkt.getSourceMAC())
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(srcIpPrefix)
                .matchIPDst(dstIpPrefix)
                .matchIPProtocol(ipv4Packet.getProtocol())
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getDestinationPort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getSourcePort()))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setIpSrc(newSrcIp)
                .setOutput(context.inPacket().receivedFrom().port())
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(FLOW_PRIORITY)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

//        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), outPort);
//        ipv4Packet.setSourceAddress(newSrcIp.toInt());
//
//        ipv4Packet.resetChecksum();
//        inPkt.setPayload(ipv4Packet);
//        inPkt.resetChecksum();
//        packetService.emit(new DefaultOutboundPacket(
//                context.inPacket().receivedFrom().deviceId(),
//                treatment,
//                ByteBuffer.wrap(inPkt.serialize())));
////        context.treatmentBuilder().setIpDst(newSrcIp).setOutput(outPort);
////        context.send();
//        context.block();
    }

    private void installSymmetricalRuleChangeSrcIpAndForward(PacketContext context, PortNumber outPort, Ip4Address newDstIp, Ip4Address newSrcIp) {
        log.info("Installing rule with src IP modification");
        Ethernet inPkt = context.inPacket().parsed();
        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(newDstIp, Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(outPort)
                .matchEthSrc(inPkt.getDestinationMAC())
                .matchEthDst(inPkt.getSourceMAC())
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(srcIpPrefix)
                .matchIPDst(dstIpPrefix)
                .matchIPProtocol(ipv4Packet.getProtocol())
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getDestinationPort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getSourcePort()))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setIpSrc(newSrcIp)
                .setOutput(context.inPacket().receivedFrom().port())
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(FLOW_PRIORITY)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

//        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), outPort);
//        ipv4Packet.setSourceAddress(newSrcIp.toInt());
//
//        ipv4Packet.resetChecksum();
//        inPkt.setPayload(ipv4Packet);
//        inPkt.resetChecksum();
//        packetService.emit(new DefaultOutboundPacket(
//                context.inPacket().receivedFrom().deviceId(),
//                treatment,
//                ByteBuffer.wrap(inPkt.serialize())));
////        context.treatmentBuilder().setIpDst(newSrcIp).setOutput(outPort);
////        context.send();
//        context.block();
    }


    private void installRuleChangeSrcIpAndForward(PacketContext context, PortNumber outPort, Ip4Address newSrcIp) {
        log.info("Installing rule with src IP modification");
        Ethernet inPkt = context.inPacket().parsed();
        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC())
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(srcIpPrefix)
                .matchIPDst(dstIpPrefix)
                .matchIPProtocol(ipv4Packet.getProtocol())
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setIpSrc(newSrcIp)
                .setOutput(outPort)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(FLOW_PRIORITY)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), outPort);
        ipv4Packet.setSourceAddress(newSrcIp.toInt());

        ipv4Packet.resetChecksum();
        inPkt.setPayload(ipv4Packet);
        inPkt.resetChecksum();
        packetService.emit(new DefaultOutboundPacket(
                context.inPacket().receivedFrom().deviceId(),
                treatment,
                ByteBuffer.wrap(inPkt.serialize())));
//        context.treatmentBuilder().setIpDst(newSrcIp).setOutput(outPort);
//        context.send();
        context.block();
    }

    private Optional<Path> pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        return paths.stream()
                .filter(path -> !path.src().port().equals(notToPort))
                .findFirst();
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            InboundPacket inPacket = context.inPacket();
            Ethernet ethPacket = inPacket.parsed();
            ConnectPoint srcConnectPoint = inPacket.receivedFrom();

            if (ethPacket == null) {
                return;
            }

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case ARP:
                    handleArpPackets(context, ethPacket, srcConnectPoint);
                    break;
                case IPV4:
                    handleFtpPackets(context, ethPacket, srcConnectPoint);
                    break;
            }
        }
    }

    private void handleArpPackets(PacketContext context, Ethernet ethPacket, ConnectPoint srcConnectPoint) {
        ARP arpPacket = (ARP) ethPacket.getPayload();

        if (arpPacket.getOpCode() != ARP.OP_REQUEST) {
            return;
        }

        Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
        Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
        if (!targetAddress.equals(sharedAddress)) {
            return;
        }

        log.info("--------------------------------------------------------------");
        log.info("Got ARP request: srcIp: {}, srcMac: {}, targetIp: {}",
                Ip4Address.valueOf(arpPacket.getSenderProtocolAddress()),
                MacAddress.valueOf(arpPacket.getSenderHardwareAddress()),
                Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()));

        // Check if it is the first device on the ARP packet path
        HostId srcHostId = HostId.hostId(MacAddress.valueOf(arpPacket.getSenderHardwareAddress()));
        Host srcHost = hostService.getHost(srcHostId);
        if (!srcConnectPoint.deviceId().equals(srcHost.location().deviceId()) ||
                !srcConnectPoint.port().equals(srcHost.location().port())
        ) {
            return;
        }

        selectNextServerIpAddress(srcIp).ifPresent((selectedServerIp) -> {
            Set<Host> hosts = hostService.getHostsByIp(selectedServerIp);
            if (hosts.size() == 0) {
                log.error("No host found for the IP address: {}", selectedServerIp);
            } else if (hosts.size() > 1) {
                log.error("Found {} hosts with the same IP address", hosts.size());
            } else {
                MacAddress selectedServerMac = hosts.iterator().next().mac();

                Ethernet arpReply = ARP.buildArpReply(targetAddress, selectedServerMac, ethPacket);
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .setOutput(srcConnectPoint.port())
                        .build();

                log.info("Emitting packet with targetMac: {} to device:port {}:{}",
                        MacAddress.valueOf(((ARP) arpReply.getPayload()).getTargetHardwareAddress()),
                        srcConnectPoint.deviceId(),
                        srcConnectPoint.port());

                packetService.emit(new DefaultOutboundPacket(
                        srcConnectPoint.deviceId(),
                        treatment,
                        ByteBuffer.wrap(arpReply.serialize())));
                context.block();
            }
        });
    }

    private void handleFtpPackets(PacketContext context, Ethernet ethPacket, ConnectPoint srcConnectPoint) {
        IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
        if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP) {
            return;
        }

        log.info("--------------------------------------------------------------");
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        if (tcpPacket.getPayload().serialize().length == 0) {
            log.info("ACK: seq: {}, ack: {}, srcPort: {}, dstPort: {}",
                    tcpPacket.getSequence(), tcpPacket.getAcknowledge(),
                    tcpPacket.getSourcePort(), tcpPacket.getDestinationPort());
            // return; // TODO delete
        }

        int srcPort = tcpPacket.getSourcePort();
        int dstPort = tcpPacket.getDestinationPort();
        if (!STANDARD_FTP_PORTS.contains(dstPort) &&
                !STANDARD_FTP_PORTS.contains(srcPort)) {
            return;
        }

        log.info("Received FTP packet from device:port {}:{}",
                srcConnectPoint.deviceId(),
                srcConnectPoint.port());

        log.info("ETH: srcMAC: {}, dstMAC: {}", ethPacket.getSourceMAC(), ethPacket.getDestinationMAC());

        log.info("IP: srcIP: {}, dstIP: {}, checksum: {}",
                Ip4Address.valueOf(ipv4Packet.getSourceAddress()),
                Ip4Address.valueOf(ipv4Packet.getDestinationAddress()),
                ipv4Packet.getChecksum());

        log.info("TCP: srcPort: {}, dstPort: {}, checksum: {}, seq: {}, ack: {}",
                tcpPacket.getSourcePort(), tcpPacket.getDestinationPort(),
                tcpPacket.getChecksum(), tcpPacket.getSequence(), tcpPacket.getAcknowledge());

        // Check if packet is for or from the shared IP address
        if (Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(sharedAddress)) { // TODO and srcAddress?
            log.info("Packet with shared address as a destination");
            FtpSessionKey key = new FtpSessionKey(PortNumber.portNumber(tcpPacket.getSourcePort()),
                    Ip4Address.valueOf(ipv4Packet.getSourceAddress()),
                    Ip4Address.valueOf(ipv4Packet.getDestinationAddress()));

            // Check if it is the first device on the packet path
            // If so add to active FTP sessions
            HostId srcHostId = HostId.hostId(ethPacket.getSourceMAC());
            Host srcHost = hostService.getHost(srcHostId);
            if (srcConnectPoint.deviceId().equals(srcHost.location().deviceId()) &&
                    srcConnectPoint.port().equals(srcHost.location().port())
            ) {
                log.info("First device on packet path");
                if (!sharedAddressRedirectForHosts.containsKey(key)) {
                    log.info("Cached host-server mapping does not contain value for key: {}", key);
                    HostId dstHostId = HostId.hostId(ethPacket.getDestinationMAC());
                    Host dstHost2 = hostService.getHost(dstHostId);
                    Ip4Address ip = dstHost2.ipAddresses().stream()
                            .filter(ipAddress -> serversAssignedToSharedAddress.contains(ipAddress.getIp4Address()))
                            .iterator().next().getIp4Address(); // TODO ignore ARP and use only dst MAC and IP
                    log.info("Putting cached address for key: {} to: {}",
                            Ip4Address.valueOf(ipv4Packet.getSourceAddress()), ip);
                    sharedAddressRedirectForHosts.put(Ip4Address.valueOf(ipv4Packet.getSourceAddress()), ip);
                }
                log.info("Adding new FTP session. Key: {}, value: {}", key,
                        sharedAddressRedirectForHosts.get(Ip4Address.valueOf(ipv4Packet.getSourceAddress())));
                activeFtpSessions.put(key,
                        sharedAddressRedirectForHosts.get(Ip4Address.valueOf(ipv4Packet.getSourceAddress())));
                log.info("Current active sessions: {}", activeFtpSessions);
                log.info("Current host-server redirects: {}", sharedAddressRedirectForHosts);
            }

            Host dstHost = hostService.getHost(HostId.hostId(ethPacket.getDestinationMAC()));
            if (dstHost == null) {
                log.error("Destination host with MAC: {} not found", ethPacket.getDestinationMAC());
                return;
            }

            // Are we on an edge switch that our destination is on?
            // If so, simply forward out to the destination and bail.
//            if (srcConnectPoint.deviceId().equals(dstHost.location().deviceId()) &&
//                    !srcConnectPoint.port().equals(dstHost.location().port())) { // TODO why?
//                log.info("We are on an edge switch: {}", srcConnectPoint.deviceId());
//                log.info("Setting new target IP for packet");
//                log.info("Current sessions: {}", activeFtpSessions);
//                Ip4Address newDstIp = activeFtpSessions.get(key);
//                log.info("Selected value: {} for key: {}", newDstIp, key);
//                installRuleAndForward(context, dstHost.location().port(), newDstIp);
//                installSymmetricalRuleChangeSrcIpAndForward(context, dstHost.location().port(), sharedAddress);
//                return;
//            }

            // Otherwise, get a set of paths that lead from here to the destination edge switch.
            Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                    srcConnectPoint.deviceId(),
                    dstHost.location().deviceId());

            if (paths.isEmpty()) {
                log.error("No paths available");
                context.block();
                return;
            }

            Ip4Address newDstIp = activeFtpSessions.get(key);
            pickForwardPathIfPossible(paths, srcConnectPoint.port())
                    .ifPresent(path -> {
                        installRuleAndForward(context, path.src().port(), newDstIp);
                        installSymmetricalRuleChangeSrcIpAndForward(context, path.src().port(), newDstIp, sharedAddress);
                    }); // TODO
            return;
        }
//        } else if (Ip4Address.valueOf(ipv4Packet.getSourceAddress()).equals(sharedAddress)) {
//            log.info("Packet with shared address as a source");
//            Host dstHost = hostService.getHost(HostId.hostId(ethPacket.getDestinationMAC()));
//            if (dstHost == null) {
//                log.error("Destination host with MAC: {} not found", ethPacket.getDestinationMAC());
//                return;
//            }
//
//            // Are we on an edge switch that our destination is on?
//            // If so, simply forward out to the destination and bail.
//            if (srcConnectPoint.deviceId().equals(dstHost.location().deviceId()) &&
//                    !srcConnectPoint.port().equals(dstHost.location().port())) { // TODO why?
//                log.info("We are on an edge switch: {}", srcConnectPoint.deviceId());
//                log.info("Simply forward.");
//                installRuleAndForward(context, dstHost.location().port());
//                return;
//            }
//
//            // Otherwise, get a set of paths that lead from here to the destination edge switch.
//            Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
//                    srcConnectPoint.deviceId(),
//                    dstHost.location().deviceId());
//
//            if (paths.isEmpty()) {
//                log.error("No paths available");
//                context.block();
//                return;
//            }
//
//            pickForwardPathIfPossible(paths, srcConnectPoint.port())
//                    .ifPresent(path -> installRuleAndForward(context, path.src().port()));
//            return;// TODO forward
//        }
//        log.info("Should be handled by FWD");
//
//        Set<Ip4Address> sharedAddresses = activeFtpSessions.keySet()
//                .stream()
//                .filter(key -> key.srcPort.equals(PortNumber.portNumber(tcpPacket.getDestinationPort())) &&
//                        key.srcIp.equals(Ip4Address.valueOf(ipv4Packet.getDestinationAddress())) &&
//                        activeFtpSessions.get(key).equals(Ip4Address.valueOf(ipv4Packet.getSourceAddress())))
//                .map(key -> key.dstIp)
//                .collect(Collectors.toSet());
//
//
//        if (sharedAddresses.size() != 1) {
//            log.error("Shared addresses size is other than 1: {}", sharedAddresses);
//        } else if (sharedAddresses.size() == 0) {
//            if (tcpPacket.getSourcePort() == 20) {
//                // TODO add FTP port to key and check if 21 session has its corresponding 20 session
//                log.info("Receiving or sending data on 20 port");
//                activeFtpSessions.put(new FtpSessionKey(tcpPacket.getDestinationPort(),
//                        Ip4Address.valueOf(ipv4Packet.getDestinationAddress()),
//                        ))
////                activeFtpSessions.keySet().stream()
////                        .filter(key -> key.)
//            }
//        } else {
//            Ip4Address sessionSharedAddress = sharedAddresses.iterator().next();
//            // Check if it is the first device on the packet path
//            // If so add to active FTP sessions
//            HostId srcHostId = HostId.hostId(ethPacket.getSourceMAC());
//            Host srcHost = hostService.getHost(srcHostId);
//            if (srcConnectPoint.deviceId().equals(srcHost.location().deviceId()) &&
//                    srcConnectPoint.port().equals(srcHost.location().port())
//            ) {
//                log.info("First device on the FTP ACK packet path");
//                Host dstHost = hostService.getHost(HostId.hostId(ethPacket.getDestinationMAC()));
//                if (dstHost == null) {
//                    log.error("Destination host with MAC: {} not found", ethPacket.getDestinationMAC());
//                    return;
//                }
//
//                // Otherwise, get a set of paths that lead from here to the destination edge switch.
//                Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
//                        srcConnectPoint.deviceId(),
//                        dstHost.location().deviceId());
//
//                if (paths.isEmpty()) {
//                    log.error("No paths available");
//                    context.block();
//                    return;
//                }
//
//                log.info("Setting new src IP to {}", sessionSharedAddress);
//                pickForwardPathIfPossible(paths, srcConnectPoint.port())
//                        .ifPresent(path -> installRuleChangeSrcIpAndForward(context, path.src().port(),
//                                sessionSharedAddress));
//                return;
//            } else {
//                log.error("Shouldn't be here");
//            }
//        }


    }
}

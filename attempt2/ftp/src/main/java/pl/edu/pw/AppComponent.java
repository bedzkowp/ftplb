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
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
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
    protected FlowObjectiveService flowObjectiveService;

    private static final String APPLICATION_NAME = "pl.edu.pw";
    private static final PacketPriority PACKET_INTERCEPT_PRIORITY = PacketPriority.MEDIUM;

    /**
     * Shared IP address
     */
    private Ip4Address sharedAddress;
    /**
     * FTP servers assigned to shared IP address
     */
    private List<Ip4Address> serversAssignedToSharedAddress = new ArrayList<>();
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
    private class FtpSessionKey {
        // private int srcPort;
        private Ip4Address srcIp;
        private Ip4Address dstIp;
    }

    private void setSharedAddress(Ip4Address newSharedAddress) {
        sharedAddress = newSharedAddress;
    }

    // TODO delete
    private static final Ip4Address TEST_SHARED_ADDRESS = Ip4Address.valueOf("10.0.1.10");
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
    }

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APPLICATION_NAME);
        // Priority must be higher (lower in number) than the FWD app (which is "director(2)")
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(1));
        requestIntercepts();
        setupTestConfig(); // TODO delete
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
                .build();

        packetService.requestPackets(arpSelector, PACKET_INTERCEPT_PRIORITY, appId);
        packetService.requestPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
    }

    private void withdrawIntercepts() {
        packetService.cancelPackets(arpSelector, PACKET_INTERCEPT_PRIORITY, appId);
        packetService.cancelPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
    }

    private Optional<Ip4Address> selectNextServerIpAddress(Ip4Address srcAddress, Ip4Address sharedAddress) {
        FtpSessionKey key = new FtpSessionKey(srcAddress, sharedAddress);
        if (activeFtpSessions.containsKey(key)) {
            return Optional.of(activeFtpSessions.get(key));
        } else {
            int index = random.nextInt(serversAssignedToSharedAddress.size());
            Ip4Address dstAddress = serversAssignedToSharedAddress.get(index);
            if (dstAddress != null) {
                activeFtpSessions.put(key, dstAddress);
            }
            return Optional.ofNullable(dstAddress);
        }
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket inPacket = context.inPacket();
            Ethernet ethPacket = inPacket.parsed();
            ConnectPoint srcConnectPoint = inPacket.receivedFrom();

            if (ethPacket == null) {
                return;
            }

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case ARP:
                    ARP arpPacket = (ARP) ethPacket.getPayload();

                    if (arpPacket.getOpCode() != ARP.OP_REQUEST) {
                        return;
                    }

                    Ip4Address sourceAddress = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
                    Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
                    if (!targetAddress.equals(sharedAddress)) {
                        return;
                    }

                    log.info("Got ARP request for the shared address: {}", arpPacket);

                    // Check if it is the first device on the ARP packet path
                    HostId srcHostId = HostId.hostId(MacAddress.valueOf(arpPacket.getSenderHardwareAddress()));
                    Host srcHost = hostService.getHost(srcHostId);
                    if (!srcConnectPoint.deviceId().equals(srcHost.location().deviceId()) ||
                            !srcConnectPoint.port().equals(srcHost.location().port())
                    ) {
                        return;
                    }

                    selectNextServerIpAddress(sourceAddress, targetAddress).ifPresent((selectedServerIp) -> {
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

                            packetService.emit(new DefaultOutboundPacket(
                                    srcConnectPoint.deviceId(),
                                    treatment,
                                    ByteBuffer.wrap(arpReply.serialize())));

                            log.info("Emitted packet to device:port {}:{}",
                                    srcConnectPoint.deviceId(),
                                    srcConnectPoint.port());
                        }
                    });
                    break;
                case IPV4:
                    IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
                    log.info("Received IPv4 packet from device/port: " + srcConnectPoint.deviceId() + "/" +
                            srcConnectPoint.port());
                    log.info("Received packet for IP: " + ethPacket);

//                    if (!Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(sharedAddress) &&
//                            !Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(Ip4Address.valueOf("10.0.1.1"))) {
//                        return;
//                    }

                    if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP) {
                        log.info("Not a TCP protocol");
                        return;
                    }

                    List<Integer> standardFtpPorts = Arrays.asList(20, 21);
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    int destinationPort = tcpPacket.getDestinationPort();
                    int srcPort = tcpPacket.getSourcePort();

                    log.info("IP packet: " + ipv4Packet);

//                    log.info("TCP src/dst port: " + destinationPort + "/" + srcPort);
//
//                    if(!standardFtpPorts.contains(destinationPort) &&
//                    !standardFtpPorts.contains(srcPort)) {
//                        log.info("NO FTP PORTS!");
//                    }

//                    if(tcpPacket.getFlags()) {
//                        log.info("Got TCP ACK: " + tcpPacket);
//                    }

                    if (standardFtpPorts.contains(destinationPort) ||
                            standardFtpPorts.contains(srcPort)) {
                        log.info("Received FTP packet: " + tcpPacket);
                        if (context.isHandled()) {
                            log.info("Context is handled");
                        }

                        if (srcConnectPoint.deviceId().equals(DeviceId.deviceId("of:0000000000000001"))) {
                            if (srcConnectPoint.port().equals(PortNumber.portNumber(4))) {
                                log.info("DEV 1, PORT 4");
                                // emitPacket(srcConnectPoint.deviceId(), ethPacket, 1);

                            } else if (srcConnectPoint.port().equals(PortNumber.portNumber(1))) {
                                log.info("DEV 1, PORT 1");
                                ipv4Packet.setSourceAddress("10.0.1.10");
                                ipv4Packet.setDestinationAddress("10.0.2.1");
                                ipv4Packet.resetChecksum();
                                ethPacket.setPayload(ipv4Packet);
                                ethPacket.setDestinationMACAddress("00:00:00:00:02:01");
                                ethPacket.resetChecksum();
                                emitPacket(srcConnectPoint.deviceId(), ethPacket, 4);
                                // context.block();
                            }
                        } else if (srcConnectPoint.deviceId().equals(DeviceId.deviceId("of:0000000000000002"))) {
                            if (srcConnectPoint.port().equals(PortNumber.portNumber(1))) {
                                log.info("DEV 2, PORT 1");
                                ipv4Packet.setDestinationAddress("10.0.1.1");
                                ipv4Packet.resetChecksum();
                                ethPacket.setPayload(ipv4Packet);
                                ethPacket.resetChecksum();
                                emitPacket(srcConnectPoint.deviceId(), ethPacket, 3);
                                // context.block();
                            } else if (srcConnectPoint.port().equals(PortNumber.portNumber(3))) {
                                log.info("DEV 2, PORT 3");
                                // emitPacket(srcConnectPoint.deviceId(), ethPacket, 1);
                            }

                        }

                        // context.block();

//                        installRules(context,
//                                srcConnectPoint.deviceId(),
//                                ethPacket.getSourceMAC(),
//                                ethPacket.getDestinationMAC(),
//                                sharedAddress,
//                                Ip4Address.valueOf("10.0.1.1"),
//                                TpPort.tpPort(tcpPacket.getSourcePort()),
//                                ethPacket,
//                                ipv4Packet,
//                                3);
//                        installNextFlow(context,
//                                DeviceId.deviceId("of:0000000000000001"),
//                                ethPacket.getSourceMAC(),
//                                ethPacket.getDestinationMAC(),
//                                sharedAddress,
//                                Ip4Address.valueOf("10.0.1.1"),
//                                TpPort.tpPort(tcpPacket.getSourcePort()),
//                                ethPacket,
//                                ipv4Packet,
//                                1);
                        return;
                    }
                    break;
            }
        }

        private void emitPacket(DeviceId deviceId, Ethernet ethPacket, int outPort) {
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(Ip4Address.valueOf("10.0.1.1"))
                    .setOutput(PortNumber.portNumber(outPort))
                    .build();
            OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                    treatment, ByteBuffer.wrap(ethPacket.serialize()));
            packetService.emit(packet);
            log.info("sending packet: {}", packet);
        }

        private void installRules(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                  Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                  Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPDst(sharedIp.toIpPrefix())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(ipDst)
                    .setOutput(PortNumber.portNumber(3))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                            .fromApp(appId)
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .withPriority(100)
                            .makeTemporary(120)
                            .add());

            ipPacket.setDestinationAddress(ipDst.toInt());
            ethPacket.setPayload(ipPacket);
            OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                    treatment, ByteBuffer.wrap(ethPacket.serialize()));
            packetService.emit(packet);
            log.info("sending packet: {}", packet);
            log.info("Context sent");

            // context.block();
            log.info("Context blocked");
        }

        private void installNextFlow(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                     Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                     Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchIPDst(ipDst.toIpPrefix())
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(1))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                            .fromApp(appId)
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .withPriority(100)
                            .makeTemporary(120)
                            .add());
        }

        private void installReverseFlow(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                        Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                        Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPDst(sharedIp.toIpPrefix())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(ipDst)
                    .setOutput(PortNumber.portNumber(3))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                            .fromApp(appId)
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .withPriority(100)
                            .makeTemporary(120)
                            .add());
        }
    }

}

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
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
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

    private static final String APPLICATION_NAME = "pl.edu.pw";
    private static final PacketPriority PACKET_INTERCEPT_PRIORITY = PacketPriority.MEDIUM;
    private static final int FLOW_PRIORITY = PACKET_INTERCEPT_PRIORITY.priorityValue() + 5;
    private static final int FLOW_TIMEOUT_IN_SEC = 180;
    /** Standard server port for a FTP session setup */
    private static final int FTP_SERVER_PORT = 21;

    /** Shared IP address */
    private Ip4Address sharedAddress;
    /** FTP servers assigned to the shared IP address */
    private List<Ip4Address> serversAssignedToSharedAddress = new ArrayList<>();
    /** Client IP mapping to a redirect IP address */
    private Map<Ip4Address, Ip4Address> clientsToRedirectIps = new HashMap<>();
    /** FTP session mapping to a redirect IP address */
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
        private PortNumber clientPort;
        private Ip4Address clientIp;
        private Ip4Address sharedIp;
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
        clientsToRedirectIps.clear();
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
        log.info("Select next server IP. Current client-redirect mapping: {}", clientsToRedirectIps);
        if (clientsToRedirectIps.containsKey(srcIp)) {
            log.info("Saved redirect IP for client: {} is: {}", srcIp, clientsToRedirectIps.get(srcIp));
            return Optional.of(clientsToRedirectIps.get(srcIp));
        } else {
            int index = random.nextInt(serversAssignedToSharedAddress.size());
            Ip4Address redirectIp = serversAssignedToSharedAddress.get(index);
            clientsToRedirectIps.put(srcIp, redirectIp);
            log.info("Select new value and add mapping: key: {} value: {}", srcIp, redirectIp);
            return Optional.ofNullable(redirectIp);
        }
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

    // TODO random MAC
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

    private void handleFtpPackets(PacketContext context, Ethernet ethPacket, ConnectPoint packetReceivedFrom) {
        IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
        if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP) {
            return;
        }
        log.info("--------------------------------------------------------------");

        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        int srcPort = tcpPacket.getSourcePort(); // TODO to portNumber
        int dstPort = tcpPacket.getDestinationPort();

        // We ignore packets from/to port 20 since they are handled by the FWD app.
        // A FTP sever is responsible for setting up a separate TCP connection for data transfer on port 20,
        // so we do not need to worry about the shared IP address.
        if (dstPort != FTP_SERVER_PORT) {
            return;
        }

        MacAddress srcMac = ethPacket.getSourceMAC();
        MacAddress dstMac = ethPacket.getDestinationMAC();
        Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());

        // For debugging purposes
        log.info("Received FTP packet from device:port {}:{}", packetReceivedFrom.deviceId(), packetReceivedFrom.port()); // TODO rename srcCOnnectPOint to receivedFrom
        log.info("ETH: srcMAC: {}, dstMAC: {}", srcMac, dstMac);
        log.info("IP: srcIP: {}, dstIP: {}, checksum: {}", srcIp, dstIp, ipv4Packet.getChecksum());
        log.info("TCP: srcPort: {}, dstPort: {}, checksum: {}, seq: {}, ack: {}", srcPort, dstPort,
                tcpPacket.getChecksum(), tcpPacket.getSequence(), tcpPacket.getAcknowledge());

        // Check if the packet is for the current shared IP address
        if (dstIp.equals(sharedAddress)) {
            log.info("Packet with shared address: {} as a destination", sharedAddress);

            Host srcHost = getHost(srcMac);
            Host dstHost = getHost(dstMac);

            // Check if it is the first device on the packet path
            if (packetReceivedFrom.deviceId().equals(srcHost.location().deviceId()) &&
                    packetReceivedFrom.port().equals(srcHost.location().port())
            ) {
                log.info("Packet arrived at first device on its path");

                // TODO ignore MAC and draw once again
                // Need to know the redirect server IP that was given by an ARP.
                // Redirect server IP may be cached at host so it won't be present in the map.
                // In such a case, need to add it manually.
                if (!clientsToRedirectIps.containsKey(srcIp)) {
                    Ip4Address redirectIp = dstHost.ipAddresses()
                            .stream()
                            .filter(ipAddress -> serversAssignedToSharedAddress.contains(ipAddress.getIp4Address()))
                            .iterator().next().getIp4Address();
                    log.info("Add client: {} to redirect IP: {} mapping", srcIp, redirectIp);
                    clientsToRedirectIps.put(srcIp, redirectIp);
                }

                // Check if there is an active FTP session for the IPs and port
                FtpSessionKey sessionKey = new FtpSessionKey(PortNumber.portNumber(srcPort), srcIp, dstIp);
                if (!activeFtpSessions.containsKey(sessionKey)) {
                    log.info("Add new FTP session: key: {} value: {}", sessionKey, clientsToRedirectIps.get(srcIp));
                    activeFtpSessions.put(sessionKey, clientsToRedirectIps.get(srcIp));
                }

                log.info("Current active FTP sessions: {}", activeFtpSessions);
                log.info("Current client-server redirects: {}", clientsToRedirectIps);

                // Get available paths that lead to the destination
                Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                        packetReceivedFrom.deviceId(),
                        dstHost.location().deviceId());

                if (paths.isEmpty()) {
                    log.error("No paths available from: {} to: {}",
                            packetReceivedFrom.deviceId(), dstHost.location().deviceId());
                    context.block();
                    return;
                }

                Ip4Address newDstIp = activeFtpSessions.get(sessionKey);
                pickForwardPathIfPossible(paths, packetReceivedFrom.port())
                        .ifPresent(path -> {
                            PortNumber outPort = path.src().port();

                            // Install rule with destination IP modification
                            log.info("Install rule with destination IP modification");
                            Ip4Prefix srcIpPrefix = Ip4Prefix.valueOf(srcIp, Ip4Prefix.MAX_MASK_LENGTH);
                            Ip4Prefix dstIpPrefix = Ip4Prefix.valueOf(dstIp, Ip4Prefix.MAX_MASK_LENGTH);

                            TrafficSelector selector = DefaultTrafficSelector.builder()
                                    .matchInPort(packetReceivedFrom.port())
                                    .matchEthSrc(srcMac)
                                    .matchEthDst(dstMac)
                                    .matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPSrc(srcIpPrefix)
                                    .matchIPDst(dstIpPrefix)
                                    .matchIPProtocol(ipv4Packet.getProtocol())
                                    .matchTcpSrc(TpPort.tpPort(srcPort))
                                    .matchTcpDst(TpPort.tpPort(dstPort))
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

                            // Install symmetrical rule with source IP modification
                            log.info("Install rule with source IP modification");
                            Ip4Prefix newDstIpPrefix = Ip4Prefix.valueOf(newDstIp, Ip4Prefix.MAX_MASK_LENGTH);

                            TrafficSelector symmetricalSelector = DefaultTrafficSelector.builder()
                                    .matchInPort(outPort)
                                    .matchEthSrc(dstMac)
                                    .matchEthDst(srcMac)
                                    .matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPSrc(newDstIpPrefix)
                                    .matchIPDst(srcIpPrefix)
                                    .matchIPProtocol(ipv4Packet.getProtocol())
                                    .matchTcpSrc(TpPort.tpPort(dstPort))
                                    .matchTcpDst(TpPort.tpPort(srcPort))
                                    .build();

                            TrafficTreatment symmetricalTreatment = DefaultTrafficTreatment.builder()
                                    .setIpSrc(dstIp)
                                    .setOutput(context.inPacket().receivedFrom().port())
                                    .build();

                            ForwardingObjective symmetricalForwardingObjective = DefaultForwardingObjective.builder()
                                    .withSelector(symmetricalSelector)
                                    .withTreatment(symmetricalTreatment)
                                    .withPriority(FLOW_PRIORITY)
                                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                                    .fromApp(appId)
                                    .makeTemporary(FLOW_TIMEOUT_IN_SEC)
                                    .add();

                            flowObjectiveService.forward(packetReceivedFrom.deviceId(), symmetricalForwardingObjective);

                            // Change destination IP and forward packet
                            log.info("Send packet to device:port {}:{}", packetReceivedFrom.deviceId(), outPort);
                            ipv4Packet.setDestinationAddress(newDstIp.toInt());
                            ipv4Packet.resetChecksum();
                            ethPacket.setPayload(ipv4Packet);
                            ethPacket.resetChecksum();
                            packetService.emit(new DefaultOutboundPacket(
                                    packetReceivedFrom.deviceId(),
                                    symmetricalTreatment,
                                    ByteBuffer.wrap(ethPacket.serialize())));
                            context.block();
                        });
            }
        }
    }

    private Host getHost(MacAddress macAddress) {
        HostId hostId = HostId.hostId(macAddress);
        Host host = hostService.getHost(hostId);
        if (host == null) {
            throw new RuntimeException("No host found for the MAC address: " + macAddress);
        } else {
            return host;
        }
    }
}

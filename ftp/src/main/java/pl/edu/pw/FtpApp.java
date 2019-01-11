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
import org.onlab.packet.ARP;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

/**
 * Application for FTP load balancig.
 */
@Component(immediate = true, service = {FtpApp.class})
public class FtpApp {

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
    protected FlowRuleService flowRuleService;

    private static final String APPLICATION_NAME = "pl.edu.pw.ftplb";
    private static final PacketPriority PACKET_INTERCEPT_PRIORITY = PacketPriority.MEDIUM;
    private static final int FLOW_PRIORITY = PACKET_INTERCEPT_PRIORITY.priorityValue() + 5;
    // Default Windows FTP server timeout + 60s = 180s
    // Default Linux FTP server timeout + 1 min = 16 min = 960 s
    private static final int FLOW_TIMEOUT_IN_SEC = 900;
    /** Standard server port for a FTP session setup */
    private static final int FTP_SERVER_PORT = 21;
    /** Locally administered MAC address for ARP handling. */
    // No manufactured host machine can have this address
    private static final MacAddress SHARED_MAC_ADDRESS = MacAddress.valueOf("02:00:00:00:00:01");
    /** Network mask */
    private static final int NETWORK_MASK = 24;

    /** Shared IP address */
    private Ip4Address sharedAddress;
    /** FTP servers assigned to the shared IP address */
    private List<Ip4Address> serversAssignedToSharedAddress = new ArrayList<>();
    /** FTP session mapping to a redirect IP address */
    private Map<FtpSessionKey, Ip4Address> activeFtpSessions = new HashMap<>();

    private FtpPacketProcessor ftpPacketProcessor = new FtpPacketProcessor();
    private FlowRuleListener ftpRuleListener = new FtpFlowListener();
    private Random random = new Random();
    private ApplicationId appId;
    private TrafficSelector ipv4Selector;

    @AllArgsConstructor
    @Getter
    @EqualsAndHashCode
    @ToString
    class FtpSessionKey {
        private PortNumber clientPort;
        private Ip4Address clientIp;
        private Ip4Address sharedIp;
    }

    Ip4Address getSharedAddress() {
        return sharedAddress;
    }

    void setSharedAddress(Ip4Address sharedAddress) {
        this.sharedAddress = sharedAddress;
        if (ipv4Selector != null) {
            log.info("Withdrawing IPv4 intercepts");
            withdrawIpv4Intercepts();
        }
        if (sharedAddress != null) {
            log.info("Requesting IPv4 intercepts");
            requestIpv4Intercepts();
        }
    }

    List<Ip4Address> getServersAssignedToSharedAddress() {
        return serversAssignedToSharedAddress;
    }

    void assignServerToSharedAddress(Ip4Address serverIp) {
        if (!serversAssignedToSharedAddress.contains(serverIp)) {
            serversAssignedToSharedAddress.add(serverIp);
        }
    }

    void unassignServerFromSharedAddress(Ip4Address serverIp) {
        serversAssignedToSharedAddress.remove(serverIp);
    }

    Map<FtpSessionKey, Ip4Address> getActiveFtpSessions() {
        return activeFtpSessions;
    }

    // For tests
    private static final Ip4Address TEST_SHARED_ADDRESS = Ip4Address.valueOf("10.0.1.20");
    private static final Ip4Address TEST_SERVER_1 = Ip4Address.valueOf("10.0.1.1");
    private static final Ip4Address TEST_SERVER_2 = Ip4Address.valueOf("10.0.1.2");
    private static final Ip4Address TEST_SERVER_3 = Ip4Address.valueOf("10.0.1.3");

    // For tests
    private void setupTestConfig() {
        setSharedAddress(TEST_SHARED_ADDRESS);
        serversAssignedToSharedAddress.add(TEST_SERVER_1);
        serversAssignedToSharedAddress.add(TEST_SERVER_2);
        serversAssignedToSharedAddress.add(TEST_SERVER_3);
    }

    // For tests
    private void clearTestConfig() {
        setSharedAddress(null);
        serversAssignedToSharedAddress.clear();
        activeFtpSessions.clear();
    }

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APPLICATION_NAME);
        // Priority must be higher (lower in number) than the FWD app (which is "director(2)")
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(1));
        flowRuleService.addListener(ftpRuleListener);
        setupTestConfig();
        requestIpv4Intercepts();
        log.info("Started: " + appId.name());
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(ftpPacketProcessor);
        flowRuleService.removeListener(ftpRuleListener);
        withdrawIpv4Intercepts();
        clearTestConfig();
        log.info("Stopped: " + appId.name());
    }

    private void requestIpv4Intercepts() {
        ipv4Selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(Ip4Prefix.valueOf(sharedAddress, Ip4Prefix.MAX_MASK_LENGTH))
                .build();
        packetService.requestPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
    }

    private void withdrawIpv4Intercepts() {
        packetService.cancelPackets(ipv4Selector, PACKET_INTERCEPT_PRIORITY, appId);
        ipv4Selector = null;
    }

    private Optional<Ip4Address> selectNextServerIpAddress() {
        if (serversAssignedToSharedAddress.size() == 0) {
            return Optional.empty();
        } else {
            int index = random.nextInt(serversAssignedToSharedAddress.size());
            Ip4Address redirectIp = serversAssignedToSharedAddress.get(index);
            return Optional.of(redirectIp);
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
            ConnectPoint packetReceivedFrom = inPacket.receivedFrom();

            if (ethPacket == null) {
                return;
            }

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case ARP:
                    handleArpPackets(context, ethPacket, packetReceivedFrom);
                    break;
                case IPV4:
                    handleFtpPackets(context, ethPacket, packetReceivedFrom);
                    break;
            }
        }
    }

    private void handleArpPackets(PacketContext context, Ethernet ethPacket, ConnectPoint packetReceivedFrom) {
        ARP arpPacket = (ARP) ethPacket.getPayload();
        if (arpPacket.getOpCode() != ARP.OP_REQUEST) {
            return;
        }

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
        Host srcHost = getHost(MacAddress.valueOf(arpPacket.getSenderHardwareAddress()));
        if (!packetReceivedFrom.deviceId().equals(srcHost.location().deviceId()) ||
                !packetReceivedFrom.port().equals(srcHost.location().port())
        ) {
            return;
        }


        Ethernet arpReply = ARP.buildArpReply(targetAddress, SHARED_MAC_ADDRESS, ethPacket);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(packetReceivedFrom.port())
                .build();

        log.info("Emitting packet with targetMac: {} to device:port {}:{}",
                MacAddress.valueOf(((ARP) arpReply.getPayload()).getTargetHardwareAddress()),
                packetReceivedFrom.deviceId(),
                packetReceivedFrom.port());

        packetService.emit(new DefaultOutboundPacket(
                packetReceivedFrom.deviceId(),
                treatment,
                ByteBuffer.wrap(arpReply.serialize())));
        context.block();
    }

    private void handleFtpPackets(PacketContext context, Ethernet ethPacket, ConnectPoint packetReceivedFrom) {
        MacAddress srcMac = ethPacket.getSourceMAC();
        MacAddress dstMac = ethPacket.getDestinationMAC();

        IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
        Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());

        // Check if the packet is for the current shared IP address
        if (dstIp.equals(sharedAddress)) {
            log.info("--------------------------------------------------------------");
            log.info("Received FTP packet from device:port {}:{}", packetReceivedFrom.deviceId(), packetReceivedFrom.port());
            log.info("ETH: srcMAC: {}, dstMAC: {}", srcMac, dstMac);
            log.info("IP: srcIP: {}, dstIP: {}, checksum: {}", srcIp, dstIp, ipv4Packet.getChecksum());

            if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP) {
                context.block();
                return;
            }

            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            int srcPort = tcpPacket.getSourcePort();
            int dstPort = tcpPacket.getDestinationPort();

            // We ignore packets from/to port 20 since they are handled by the FWD app.
            // A FTP sever is responsible for setting up a separate TCP connection for data transfer on port 20,
            // so we do not need to worry about the shared IP address.
            if (dstPort != FTP_SERVER_PORT &&
                    (srcPort != 20 && dstPort != 20)) {
                context.block();
                return;
            }

            // For debugging purposes
            log.info("TCP: srcPort: {}, dstPort: {}, checksum: {}, seq: {}, ack: {}", srcPort, dstPort,
                    tcpPacket.getChecksum(), tcpPacket.getSequence(), tcpPacket.getAcknowledge());

            Host srcHost = getHost(srcMac);

            // Check if it is the first device on the packet path
            if (packetReceivedFrom.deviceId().equals(srcHost.location().deviceId()) &&
                    packetReceivedFrom.port().equals(srcHost.location().port())
            ) {
                log.info("Packet arrived at first device on its path");

                // Check if there is an active FTP session for the IPs and port
                FtpSessionKey sessionKey = new FtpSessionKey(PortNumber.portNumber(srcPort), srcIp, dstIp);
                if (!activeFtpSessions.containsKey(sessionKey)) {
                    Optional<Ip4Address> optionalRedirectIp = selectNextServerIpAddress();
                    if (optionalRedirectIp.isPresent()) {
                        Ip4Address redirectIp = optionalRedirectIp.get();
                        log.info("Add new FTP session: key: {} value: {}", sessionKey, redirectIp);
                        activeFtpSessions.put(sessionKey, redirectIp);
                    } else {
                        log.warn("No IP for redirect.");
                        context.block();
                        return;
                    }
                }
                log.info("Current active FTP sessions: {}", activeFtpSessions);

                Ip4Address newDstIp = activeFtpSessions.get(sessionKey);
                Host dstHost = hostService.getHostsByIp(newDstIp).iterator().next();
                MacAddress newDstMac = dstHost.mac();

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
                                    .matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPSrc(srcIpPrefix)
                                    .matchIPDst(dstIpPrefix)
                                    .matchIPProtocol(ipv4Packet.getProtocol())
                                    .matchTcpSrc(TpPort.tpPort(srcPort))
                                    .matchTcpDst(TpPort.tpPort(dstPort))
                                    .build();

                            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .setIpDst(newDstIp)
                                    .setEthDst(newDstMac)
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
                                    .matchEthSrc(newDstMac)
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
                            ethPacket.setDestinationMACAddress(newDstMac);
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

    // Listens for removed flows and drop sessions
    private class FtpFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            handleEvent(event);
        }
    }

    private void handleEvent(FlowRuleEvent event) {
        FlowRule flowRule = event.subject();
        if (event.type() == FlowRuleEvent.Type.RULE_REMOVED && flowRule.appId() == appId.id()) {
            IPCriterion srcIpCriterion = (IPCriterion) flowRule.selector().getCriterion(Criterion.Type.IPV4_SRC);
            IPCriterion dstIpCriterion = (IPCriterion) flowRule.selector().getCriterion(Criterion.Type.IPV4_DST);
            TcpPortCriterion srcPortCriterion = (TcpPortCriterion) flowRule.selector().getCriterion(Criterion.Type.TCP_SRC);

            Ip4Address srcIp = srcIpCriterion.ip().getIp4Prefix().address();
            Ip4Address dstIp = dstIpCriterion.ip().getIp4Prefix().address();
            PortNumber srcPort = PortNumber.portNumber(srcPortCriterion.tcpPort().toInt());

            FtpSessionKey sessionKey = new FtpSessionKey(srcPort, srcIp, dstIp);
            Ip4Address value = activeFtpSessions.remove(sessionKey);
            log.info("Removed session: {}, value: {} due to flow removal", sessionKey, value);
        }
    }

    public void validateSharedIpAddress(Ip4Address sharedIp) throws ConflictException, NotFoundException {
        if (hostService.getHostsByIp(sharedIp).size() != 0) {
            throw new ConflictException("IP: " + sharedIp + " address already allocated.");
        }

        if (serversAssignedToSharedAddress.size() > 0) {
            Ip4Address serverIp = serversAssignedToSharedAddress.get(0);
            Ip4Prefix serverIpPrefix = Ip4Prefix.valueOf(serverIp.toInt(), NETWORK_MASK);
            Ip4Prefix sharedIpPrefix = Ip4Prefix.valueOf(sharedIp.toInt(), NETWORK_MASK);
            log.info("Server IP (network) prefix: {}, shared IP prefix: {}", serverIpPrefix, sharedIpPrefix);
            if (!sharedIpPrefix.equals(serverIpPrefix)) {
                throw new ConflictException("Shared IP prefix must correspond to the servers IP prefixes");
            }
        }
    }

    public void validateFtpServerAddress(Ip4Address serverIp) throws ConflictException, NotFoundException {
        if (hostService.getHostsByIp(serverIp).size() == 0) {
            throw new NotFoundException("Server with IP: " + serverIp + " not found");
        }

        if (sharedAddress != null) {
            Ip4Prefix sharedAddressPrefix = Ip4Prefix.valueOf(sharedAddress.toInt(), NETWORK_MASK);
            Ip4Prefix serverIpPrefix = Ip4Prefix.valueOf(serverIp.toInt(), NETWORK_MASK);
            log.info("Server IP (network) prefix: {}, shared address prefix: {}", serverIpPrefix, sharedAddressPrefix);
            if (!serverIpPrefix.equals(sharedAddressPrefix)) {
                throw new ConflictException("Server IP prefix must correspond to the shared IP prefix");
            }
        }
    }

    public class ConflictException extends RuntimeException {

        ConflictException(String message) {
            super(message);
        }

    }

    public class NotFoundException extends RuntimeException {

        NotFoundException(String message) {
            super(message);
        }

    }
}

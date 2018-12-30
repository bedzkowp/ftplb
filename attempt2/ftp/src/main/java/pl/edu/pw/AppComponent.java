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
    private static final PacketPriority PACKET_INTERCEPT_PRIORITY = PacketPriority.REACTIVE;
    private static final List<Integer> STANDARD_FTP_PORTS = Arrays.asList(20, 21);

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

    private Optional<Path> pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        return paths.stream()
                .filter(path -> !path.src().port().equals(notToPort))
                .findFirst();
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {
        log.info("Installing rule");
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC());


        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        byte ipv4Protocol = ipv4Packet.getProtocol();
        Ip4Prefix matchIp4SrcPrefix =
                Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                        Ip4Prefix.MAX_MASK_LENGTH);
        Ip4Prefix matchIp4DstPrefix =
                Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                        Ip4Prefix.MAX_MASK_LENGTH);
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(matchIp4SrcPrefix)
                .matchIPDst(matchIp4DstPrefix);

        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        selectorBuilder.matchIPProtocol(ipv4Protocol)
                .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(15)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(10)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);

        log.info("Sending to device:port {}:{}", context.inPacket().receivedFrom().deviceId(), portNumber);
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
        context.block();
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
//            if (context.isHandled()) {
//                return;
//            }

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

                            log.info("Emitting packet with targetMac: {} to device:port {}:{}",
                                    MacAddress.valueOf(((ARP) arpReply.getPayload()).getTargetHardwareAddress()),
                                    srcConnectPoint.deviceId(),
                                    srcConnectPoint.port());

                            packetService.emit(new DefaultOutboundPacket(
                                    srcConnectPoint.deviceId(),
                                    treatment,
                                    ByteBuffer.wrap(arpReply.serialize())));
                        }
                    });
                    break;
                case IPV4:
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
                        // return;
                    }

                    int destinationPort = tcpPacket.getDestinationPort();
                    if (!STANDARD_FTP_PORTS.contains(destinationPort)) { // TODO or srcPort?
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

                    // Check if packet is for or from the shared IP addresss
                    if (!Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(sharedAddress)) { // TODO and srcAddress?
                        return;
                    }

                    Host dstHost = hostService.getHost(HostId.hostId(ethPacket.getDestinationMAC()));
                    if (dstHost == null) {
                        log.error("Destination host with MAC: {} not found", ethPacket.getDestinationMAC());
                        return;
                    }

                    // Are we on an edge switch that our destination is on?
                    // If so, simply forward out to the destination and bail.
                    if (srcConnectPoint.deviceId().equals(dstHost.location().deviceId()) &&
                            !srcConnectPoint.port().equals(dstHost.location().port())) { // TODO why?
                        log.info("We are on an edge switch: {}", srcConnectPoint.deviceId());
                        installRule(context, dstHost.location().port());
                        return;
                    }

                    // Otherwise, get a set of paths that lead from here to the destination edge switch.
                    Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                            srcConnectPoint.deviceId(),
                            dstHost.location().deviceId());

                    if (paths.isEmpty()) {
                        log.error("No paths available");
                        context.block();
                        return;
                    }

                    pickForwardPathIfPossible(paths, srcConnectPoint.port())
                            .ifPresent(path -> installRule(context, path.src().port()));
            }
        }
    }
}
